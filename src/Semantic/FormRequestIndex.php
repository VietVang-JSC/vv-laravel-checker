<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Semantic;

use PhpParser\Node;
use PhpParser\NodeFinder;
use PhpParser\ParserFactory;

/**
 * FormRequest semantics per scanned project: resolve a controller
 * parameter to its request class, then expose validation evidence
 * (`rules()` presence + fields) and authorization evidence
 * (`authorize()` classification) as composable objects.
 *
 * Conservative throughout:
 * - Inheritance is confirmed only by a direct `extends FormRequest`
 *   (resolved through imports). Name heuristics apply solely when the
 *   class file is absent from the scan.
 * - `rules()` presence counts even when its body is dynamic — but then
 *   fields are unknown and confidence drops to medium. A missing
 *   `rules()` method is no validation evidence at all.
 * - `authorize()` returning literal `true` (or absent) is explicitly
 *   not authorization. `can`/`Gate` ability checks and explicit denies
 *   are strong evidence; other non-trivial bodies are custom (medium).
 */
final class FormRequestIndex
{
    /**
     * @var array<string, array{fqn: string, file: string, line: int, extends_form_request: bool, has_rules: bool, fields: list<string>|null, rules_confidence: string, authorize: string, authorize_confidence: string, ability: string|null}>
     *   lowercase FQCN => entry
     */
    private array $requests = [];

    /**
     * @param list<string> $files
     */
    public function build(array $files): self
    {
        foreach ($files as $file) {
            if (strtolower((string) pathinfo($file, PATHINFO_EXTENSION)) !== 'php') {
                continue;
            }
            // Bound the parse surface: request classes live in
            // *Request.php files by convention.
            if (!str_ends_with(strtolower((string) pathinfo($file, PATHINFO_BASENAME)), 'request.php')) {
                continue;
            }
            $this->collectFromFile($file);
        }

        return $this;
    }

    /**
     * @return array{fqn: string, file: string, line: int, extends_form_request: bool, has_rules: bool, fields: list<string>|null, rules_confidence: string, authorize: string, authorize_confidence: string, ability: string|null}|null
     */
    public function find(string $fqn): ?array
    {
        return $this->requests[strtolower(ltrim($fqn, '\\'))] ?? null;
    }

    public function validationEvidence(string $fqn): ?ValidationEvidence
    {
        $entry = $this->find($fqn);
        if ($entry === null || !$entry['has_rules']) {
            return null;
        }

        return new ValidationEvidence(
            ValidationEvidence::SOURCE_FORM_REQUEST,
            $entry['fqn'],
            true,
            $entry['fields'],
            $entry['rules_confidence']
        );
    }

    public function authorizationEvidence(string $fqn): ?AuthorizationEvidence
    {
        $entry = $this->find($fqn);
        if ($entry === null) {
            return null;
        }
        $mechanism = match ($entry['authorize']) {
            'strong' => $entry['ability'] === 'deny-all'
                ? AuthorizationEvidence::MECH_DENY
                : AuthorizationEvidence::MECH_CAN,
            'custom' => AuthorizationEvidence::MECH_CUSTOM,
            default => AuthorizationEvidence::MECH_NONE,
        };
        if ($mechanism === AuthorizationEvidence::MECH_NONE) {
            return null;
        }

        return new AuthorizationEvidence(
            AuthorizationEvidence::SOURCE_FORM_REQUEST,
            $entry['fqn'],
            $mechanism,
            $entry['ability'] === 'deny-all' ? null : $entry['ability'],
            $entry['authorize_confidence']
        );
    }

    private function collectFromFile(string $file): void
    {
        $code = is_file($file) ? file_get_contents($file) : false;
        if (!is_string($code) || $code === '') {
            return;
        }
        try {
            $ast = (new ParserFactory())->createForNewestSupportedVersion()->parse($code);
        } catch (\Throwable $e) {
            return;
        }
        if ($ast === null) {
            return;
        }
        $finder = new NodeFinder();
        $uses = $this->useMap($finder, $ast);
        $namespace = $this->namespaceOf($finder, $ast);
        $classes = $finder->findInstanceOf($ast, Node\Stmt\Class_::class);
        foreach ($classes as $class) {
            if (!$class instanceof Node\Stmt\Class_ || $class->name === null) {
                continue;
            }
            $short = $class->name->toString();
            if (!str_ends_with($short, 'Request')) {
                continue;
            }
            $fqn = $namespace !== null ? $namespace . '\\' . $short : $short;
            $key = strtolower($fqn);
            if (isset($this->requests[$key])) {
                continue;
            }
            $rules = $this->analyzeRules($class);
            $auth = $this->analyzeAuthorize($class);
            $this->requests[$key] = [
                'fqn' => $fqn,
                'file' => $file,
                'line' => $class->getStartLine(),
                'extends_form_request' => $this->extendsFormRequest($class, $uses, $namespace),
                'has_rules' => $rules['has_rules'],
                'fields' => $rules['fields'],
                'rules_confidence' => $rules['confidence'],
                'authorize' => $auth['kind'],
                'authorize_confidence' => $auth['confidence'],
                'ability' => $auth['ability'],
            ];
        }
    }

    /**
     * @return array{has_rules: bool, fields: list<string>|null, confidence: string}
     */
    private function analyzeRules(Node\Stmt\Class_ $class): array
    {
        foreach ($class->stmts as $stmt) {
            if (
                !$stmt instanceof Node\Stmt\ClassMethod
                || strtolower($stmt->name->toString()) !== 'rules'
            ) {
                continue;
            }
            if ($stmt->stmts === null || count($stmt->stmts) !== 1) {
                return ['has_rules' => true, 'fields' => null, 'confidence' => 'medium'];
            }
            $only = $stmt->stmts[0];
            if (!$only instanceof Node\Stmt\Return_ || !$only->expr instanceof Node\Expr\Array_) {
                // Dynamic rules (variable, conditional, config()): the
                // layer exists but fields are unknown — never guessed.
                return ['has_rules' => true, 'fields' => null, 'confidence' => 'medium'];
            }
            $fields = [];
            foreach ($only->expr->items as $item) {
                if (!$item instanceof Node\Expr\ArrayItem || !$item->key instanceof Node\Scalar\String_) {
                    return ['has_rules' => true, 'fields' => null, 'confidence' => 'medium'];
                }
                $fields[] = $item->key->value;
            }

            return ['has_rules' => true, 'fields' => $fields, 'confidence' => 'high'];
        }

        return ['has_rules' => false, 'fields' => null, 'confidence' => 'medium'];
    }

    /**
     * @return array{kind: string, confidence: string, ability: string|null}
     *   kind: none|strong|custom
     */
    private function analyzeAuthorize(Node\Stmt\Class_ $class): array
    {
        foreach ($class->stmts as $stmt) {
            if (
                !$stmt instanceof Node\Stmt\ClassMethod
                || strtolower($stmt->name->toString()) !== 'authorize'
            ) {
                continue;
            }
            if ($stmt->stmts === null || $stmt->stmts === []) {
                return ['kind' => 'custom', 'confidence' => 'medium', 'ability' => null];
            }
            if (
                count($stmt->stmts) === 1
                && $stmt->stmts[0] instanceof Node\Stmt\Return_
                && $stmt->stmts[0]->expr instanceof Node\Expr\ConstFetch
            ) {
                $name = strtolower($stmt->stmts[0]->expr->name->toString());
                if ($name === 'true') {
                    return ['kind' => 'none', 'confidence' => 'high', 'ability' => null];
                }
                if ($name === 'false') {
                    // Deny-all: a decision, and a protective one.
                    return ['kind' => 'strong', 'confidence' => 'high', 'ability' => 'deny-all'];
                }
            }
            $finder = new NodeFinder();
            $ability = null;
            $strong = $finder->find($stmt->stmts, function (Node $node) use (&$ability): bool {
                if (
                    $node instanceof Node\Expr\MethodCall
                    && $node->name instanceof Node\Identifier
                    && in_array(strtolower($node->name->toString()), ['can', 'allows', 'authorize', 'denies'], true)
                ) {
                    $ability ??= $this->firstStringArg($node);
                    if ($this->isUserish($node->var)) {
                        return true;
                    }
                }
                if (
                    $node instanceof Node\Expr\StaticCall
                    && $node->class instanceof Node\Name
                    && $this->shortClass($node->class->toString()) === 'Gate'
                    && $node->name instanceof Node\Identifier
                    && in_array(strtolower($node->name->toString()), ['allows', 'authorize', 'denies', 'check', 'any'], true)
                ) {
                    $ability ??= $this->firstStringArg($node);

                    return true;
                }
                if ($node instanceof Node\Expr\Throw_) {
                    return true;
                }
                if (
                    $node instanceof Node\Expr\FuncCall
                    && $node->name instanceof Node\Name
                    && in_array(strtolower($node->name->toString()), ['abort', 'abort_if', 'abort_unless'], true)
                ) {
                    return true;
                }
                if ($node instanceof Node\Scalar\Int_ && $node->value === 403) {
                    return true;
                }

                return false;
            });
            if ($strong !== []) {
                return ['kind' => 'strong', 'confidence' => 'high', 'ability' => $ability];
            }

            return ['kind' => 'custom', 'confidence' => 'medium', 'ability' => null];
        }

        return ['kind' => 'none', 'confidence' => 'high', 'ability' => null];
    }

    private function firstStringArg(Node\Expr\StaticCall|Node\Expr\MethodCall $node): ?string
    {
        $arg = $node->args[0] ?? null;
        if ($arg instanceof Node\Arg && $arg->value instanceof Node\Scalar\String_) {
            return $arg->value->value;
        }

        return null;
    }

    private function isUserish(Node\Expr $var): bool
    {
        if ($var instanceof Node\Expr\Variable) {
            return in_array($var->name, ['this', 'request', 'user'], true);
        }
        if ($var instanceof Node\Expr\MethodCall || $var instanceof Node\Expr\PropertyFetch) {
            return $var->var instanceof Node\Expr && $this->isUserish($var->var);
        }
        if ($var instanceof Node\Expr\StaticCall) {
            return $var->class instanceof Node\Name
                && in_array($this->shortClass($var->class->toString()), ['Auth', 'Gate'], true);
        }
        if ($var instanceof Node\Expr\FuncCall) {
            return $var->name instanceof Node\Name
                && in_array(strtolower($var->name->toString()), ['auth', 'user'], true);
        }

        return false;
    }

    /**
     * @param array<string, string> $uses
     */
    private function extendsFormRequest(Node\Stmt\Class_ $class, array $uses, ?string $namespace): bool
    {
        if (!$class->extends instanceof Node\Name) {
            return false;
        }
        $name = $class->extends->toString();
        if ($class->extends instanceof Node\Name\FullyQualified) {
            return $name === 'Illuminate\\Foundation\\Http\\FormRequest';
        }
        $pos = strpos($name, '\\');
        if ($pos !== false) {
            $first = strtolower(substr($name, 0, $pos));
            $resolved = isset($uses[$first]) ? $uses[$first] . substr($name, $pos) : $name;

            return $resolved === 'Illuminate\\Foundation\\Http\\FormRequest';
        }
        $lower = strtolower($name);
        if (isset($uses[$lower])) {
            return $uses[$lower] === 'Illuminate\\Foundation\\Http\\FormRequest';
        }

        return $lower === 'formrequest' && $namespace !== null
            && str_ends_with($namespace, 'Http\\Requests');
    }

    /**
     * @param list<Node> $nodes
     * @return array<string, string>
     */
    private function useMap(NodeFinder $finder, array $nodes): array
    {
        $map = [];
        $imports = $finder->find($nodes, static function (Node $node): bool {
            return $node instanceof Node\Stmt\Use_ || $node instanceof Node\Stmt\GroupUse;
        });
        foreach ($imports as $import) {
            if ($import instanceof Node\Stmt\GroupUse) {
                foreach ($import->uses as $use) {
                    if (!$use instanceof Node\Stmt\UseUse) {
                        continue;
                    }
                    $alias = $use->alias !== null ? $use->alias->toString() : $use->name->getLast();
                    $map[strtolower($alias)] = $import->prefix->toString() . '\\' . $use->name->toString();
                }
                continue;
            }
            if (!$import instanceof Node\Stmt\Use_ || $import->type !== Node\Stmt\Use_::TYPE_NORMAL) {
                continue;
            }
            foreach ($import->uses as $use) {
                if (!$use instanceof Node\Stmt\UseUse) {
                    continue;
                }
                $alias = $use->alias !== null ? $use->alias->toString() : $use->name->getLast();
                $map[strtolower($alias)] = $use->name->toString();
            }
        }

        return $map;
    }

    /**
     * @param list<Node> $nodes
     */
    private function namespaceOf(NodeFinder $finder, array $nodes): ?string
    {
        $found = $finder->find($nodes, static function (Node $node): bool {
            return $node instanceof Node\Stmt\Namespace_;
        });
        foreach ($found as $node) {
            if ($node instanceof Node\Stmt\Namespace_ && $node->name instanceof Node\Name) {
                return $node->name->toString();
            }
        }

        return null;
    }

    private function shortClass(string $class): string
    {
        $trimmed = ltrim($class, '\\');
        $pos = strrpos($trimmed, '\\');

        return $pos === false ? $trimmed : substr($trimmed, $pos + 1);
    }
}
