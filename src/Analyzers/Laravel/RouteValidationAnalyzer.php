<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Analyzers\Laravel;

use PhpParser\Node;
use Rampart\QualityChecker\Analyzers\AbstractAnalyzer;
use Rampart\QualityChecker\Result\Confidence;
use Rampart\QualityChecker\Result\Issue;
use Rampart\QualityChecker\Result\Severity;

/**
 * Request validation on mutating controller actions.
 *
 * Flags controller methods that mutate state (store/update/delete/destroy and
 * the like) yet perform no validation:
 *  - no `$request->validate(...)` / `Validator::make(...)` / `->validate()`
 *    call in the body
 *  - no FormRequest (a class ending in `Request`) injected as a parameter
 *  - no `->validate()` on a model / validated() usage
 *
 * Assumes: only concrete controller classes (name ends in "Controller", not
 * abstract) are inspected. Confidence is medium because validation may be
 * delegated to a service or route middleware.
 */
final class RouteValidationAnalyzer extends AbstractAnalyzer
{
    private const RULE = 'ROUTE_MISSING_VALIDATION';

    private const MUTATING_METHODS = [
        'store', 'update', 'delete', 'destroy', 'restore', 'forceDelete',
    ];

    private const VALIDATION_CALLS = [
        'validate', 'validated', 'make', 'validateWithBag',
    ];

    public function analyze(array $files): array
    {
        $issues = [];
        foreach ($files as $file) {
            if (!$this->supports($file)) {
                continue;
            }
            foreach ($this->analyzeFile($file) as $issue) {
                $issues[] = $issue;
            }
        }

        return $issues;
    }

    private function analyzeFile(string $file): array
    {
        $ast = $this->parse($this->readFile($file));
        if ($ast === null) {
            return [];
        }

        $issues = [];
        $classes = $this->finder()->findInstanceOf($ast, Node\Stmt\Class_::class);
        $useMap = $this->useMap($ast);

        foreach ($classes as $class) {
            if (!$class instanceof Node\Stmt\Class_ || !$this->isControllerClass($class)) {
                continue;
            }
            foreach ($this->analyzeController($class, $file, $useMap) as $issue) {
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
    private function analyzeController(Node\Stmt\Class_ $class, string $file, array $useMap): array
    {
        $issues = [];

        foreach ($class->stmts as $stmt) {
            if (!$stmt instanceof Node\Stmt\ClassMethod || !$stmt->isPublic()) {
                continue;
            }

            $name = $stmt->name->toString();
            if (!in_array($name, self::MUTATING_METHODS, true)) {
                continue;
            }

            if ($this->hasFormRequest($stmt, $useMap) || $this->bodyHasValidation($stmt)) {
                continue;
            }

            $issues[] = $this->makeIssue(
                self::RULE,
                sprintf('Mutating method %s() performs no request validation (no $request->validate/FormRequest).', $name),
                $file,
                $stmt->getStartLine(),
                Severity::Warning,
                ['method' => $name],
                Confidence::Medium
            );
        }

        return $issues;
    }

    /**
     * @param array<string, string> $useMap alias => FQCN
     */
    private function hasFormRequest(Node\Stmt\ClassMethod $method, array $useMap): bool
    {
        foreach ($method->params as $param) {
            if (!$param->type instanceof Node\Name) {
                continue;
            }

            $type = $param->type->toString();
            // Resolve short names through use-imports: `store(StoreRequest
            // $request)` with `use App\Http\Requests\StoreRequest;` is a
            // FormRequest even though the hint has no backslash.
            if (!str_contains($type, '\\') && isset($useMap[$type])) {
                $type = $useMap[$type];
            }

            // Real FormRequest: either the Laravel base class or a custom
            // *Request inside a `Requests\` namespace. Plain `Illuminate\Http\Request`
            // is NOT a FormRequest.
            if (str_ends_with($type, 'FormRequest')) {
                return true;
            }

            if (
                str_contains($type, '\\')
                && str_ends_with($type, 'Request')
                && stripos($type, 'Requests\\') !== false
            ) {
                return true;
            }
        }

        return false;
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

    private function bodyHasValidation(Node\Stmt\ClassMethod $method): bool
    {
        if ($method->stmts === null) {
            return false;
        }

        $found = $this->finder()->find($method->stmts, function (Node $node): bool {
            if ($node instanceof Node\Expr\MethodCall && $node->name instanceof Node\Identifier) {
                return in_array($node->name->toString(), self::VALIDATION_CALLS, true);
            }

            if (
                $node instanceof Node\Expr\StaticCall
                && $node->class instanceof Node\Name
                && str_ends_with($node->class->toString(), 'Validator')
            ) {
                return true;
            }

            return false;
        });

        return $found !== [];
    }
}
