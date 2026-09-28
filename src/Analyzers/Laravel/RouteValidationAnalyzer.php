<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Analyzers\Laravel;

use PhpParser\Node;
use Rampart\QualityChecker\Analyzers\AbstractAnalyzer;
use Rampart\QualityChecker\Result\Confidence;
use Rampart\QualityChecker\Result\Issue;
use Rampart\QualityChecker\Result\Severity;
use Rampart\QualityChecker\Semantic\FormRequestIndex;
use Rampart\QualityChecker\Semantic\InlineValidation;
use Rampart\QualityChecker\Semantic\ValidationEvidence;

/**
 * Request validation on mutating controller actions.
 *
 * Flags controller methods that mutate state (store/update/delete/destroy and
 * the like) yet carry no validation evidence:
 *  - a FormRequest parameter whose class resolves to `rules()` (fields may
 *    be known or unknown — presence of the layer counts; a resolved
 *    FormRequest *without* `rules()` is not evidence)
 *  - `$request->validate(...)` / `Validator::make(...)` in the body
 *  - `validated()` / `safe()` use (validated-data source)
 *
 * An unresolvable `*Request` type-hint keeps the legacy name-heuristic
 * suppression (low confidence). Assumes: only concrete controller classes
 * (name ends in "Controller", not abstract) are inspected. Confidence is
 * medium because validation may be delegated to a service or middleware.
 */
final class RouteValidationAnalyzer extends AbstractAnalyzer
{
    private const RULE = 'ROUTE_MISSING_VALIDATION';

    private const MUTATING_METHODS = [
        'store', 'update', 'delete', 'destroy', 'restore', 'forceDelete',
    ];

    public function analyze(array $files): array
    {
        $index = (new FormRequestIndex())->build($files);

        $issues = [];
        foreach ($files as $file) {
            if (!$this->supports($file)) {
                continue;
            }
            foreach ($this->analyzeFile($file, $index) as $issue) {
                $issues[] = $issue;
            }
        }

        return $issues;
    }

    private function analyzeFile(string $file, FormRequestIndex $index): array
    {
        $ast = $this->parse($this->readFile($file));
        if ($ast === null) {
            return [];
        }

        $issues = [];
        $classes = $this->finder()->findInstanceOf($ast, Node\Stmt\Class_::class);
        $useMap = $this->useMap($ast);
        $namespace = $this->namespaceOf($ast);

        foreach ($classes as $class) {
            if (!$class instanceof Node\Stmt\Class_ || !$this->isControllerClass($class)) {
                continue;
            }
            foreach ($this->analyzeController($class, $file, $useMap, $namespace, $index) as $issue) {
                $issues[] = $issue;
            }
        }

        return $issues;
    }

    private function isControllerClass(Node\Stmt\Class_ $class): bool
    {
        if ($class->name === null || $class->isAbstract()) {
            return false;
        }

        return str_ends_with($class->name->toString(), 'Controller');
    }

    /**
     * @param array<string, string> $useMap
     * @return Issue[]
     */
    private function analyzeController(
        Node\Stmt\Class_ $class,
        string $file,
        array $useMap,
        ?string $namespace,
        FormRequestIndex $index
    ): array {
        $issues = [];

        foreach ($class->stmts as $stmt) {
            if (!$stmt instanceof Node\Stmt\ClassMethod || !$stmt->isPublic()) {
                continue;
            }

            $name = $stmt->name->toString();
            if (!in_array($name, self::MUTATING_METHODS, true)) {
                continue;
            }

            if ($this->validationEvidence($stmt, $useMap, $namespace, $index) !== null) {
                continue;
            }

            $issues[] = $this->makeIssue(
                self::RULE,
                sprintf('Mutating method %s() performs no request validation (no $request->validate/FormRequest).', $name),
                $file,
                $stmt->getStartLine(),
                Severity::Warning,
                ['method' => $name, 'validation_evidence' => null],
                Confidence::Medium
            );
        }

        return $issues;
    }

    /**
     * @param array<string, string> $useMap alias => FQCN
     */
    private function validationEvidence(
        Node\Stmt\ClassMethod $method,
        array $useMap,
        ?string $namespace,
        FormRequestIndex $index
    ): ?ValidationEvidence {
        foreach ($method->params as $param) {
            if (!$param->type instanceof Node\Name) {
                continue;
            }
            $fqn = $this->resolveParam($param->type->toString(), $useMap, $namespace);
            $evidence = $index->validationEvidence($fqn);
            if ($evidence instanceof ValidationEvidence) {
                return $evidence;
            }
            // Legacy name-heuristic fallback for request classes absent
            // from the scan (low confidence, preserves behavior).
            if ($index->find($fqn) === null && $this->looksLikeFormRequest($param->type->toString(), $useMap)) {
                return new ValidationEvidence(
                    ValidationEvidence::SOURCE_FORM_REQUEST,
                    $fqn,
                    true,
                    null,
                    'low'
                );
            }
        }

        $inline = InlineValidation::recognize($method);

        return $inline[0] ?? null;
    }

    /**
     * @param array<string, string> $useMap alias => FQCN
     */
    private function resolveParam(string $type, array $useMap, ?string $namespace): string
    {
        if (str_starts_with($type, '\\')) {
            return ltrim($type, '\\');
        }
        if (!str_contains($type, '\\') && isset($useMap[$type])) {
            return $useMap[$type];
        }
        $pos = strpos($type, '\\');
        if ($pos !== false) {
            $first = substr($type, 0, $pos);
            if (isset($useMap[$first])) {
                return $useMap[$first] . substr($type, $pos);
            }
        }

        return $namespace !== null ? $namespace . '\\' . $type : $type;
    }

    /**
     * Legacy name heuristic for request classes absent from the scan:
     * the Laravel base class or a custom *Request inside a `Requests\`
     * namespace. Plain `Illuminate\Http\Request` is NOT a FormRequest.
     *
     * @param array<string, string> $useMap alias => FQCN
     */
    private function looksLikeFormRequest(string $type, array $useMap): bool
    {
        // Resolve short names through use-imports: `store(StoreRequest
        // $request)` with `use App\Http\Requests\StoreRequest;` is a
        // FormRequest even though the hint has no backslash.
        if (!str_contains($type, '\\') && isset($useMap[$type])) {
            $type = $useMap[$type];
        }

        if (str_ends_with($type, 'FormRequest')) {
            return true;
        }

        return str_contains($type, '\\')
            && str_ends_with($type, 'Request')
            && stripos($type, 'Requests\\') !== false;
    }

    /**
     * @param list<Node> $ast
     * @return array<string, string> alias => FQCN
     */
    private function useMap(array $ast): array
    {
        $map = [];
        /** @var list<Node\Stmt\Use_> $uses */
        $uses = $this->finder()->findInstanceOf($ast, Node\Stmt\Use_::class);
        foreach ($uses as $use) {
            foreach ($use->uses as $useUse) {
                $alias = $useUse->alias !== null
                    ? $useUse->alias->toString()
                    : $useUse->name->getLast();
                $map[$alias] = $useUse->name->toString();
            }
        }

        return $map;
    }

    /**
     * @param list<Node> $ast
     */
    private function namespaceOf(array $ast): ?string
    {
        $found = $this->finder()->find($ast, static function (Node $node): bool {
            return $node instanceof Node\Stmt\Namespace_;
        });
        foreach ($found as $node) {
            if ($node instanceof Node\Stmt\Namespace_ && $node->name instanceof Node\Name) {
                return $node->name->toString();
            }
        }

        return null;
    }
}
