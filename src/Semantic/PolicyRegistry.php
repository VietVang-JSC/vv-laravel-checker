<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Semantic;

use PhpParser\Node;
use PhpParser\NodeFinder;
use Rampart\QualityChecker\Analysis\CountingNodeFinder;
use Rampart\QualityChecker\Scanning\ScanContextAware;
use Rampart\QualityChecker\Scanning\ScanContextTrait;

/**
 * Tier 1 policy/Gate registration: model → policy and ability → define
 * mappings. Symbol resolution only — never authorization by name.
 *
 * Sources understood (bounded):
 * - `protected $policies = [Post::class => PostPolicy::class]` in any
 *   `*ServiceProvider.php` (typically `AuthServiceProvider`).
 * - `Gate::policy(Post::class, PostPolicy::class)` calls in providers.
 * - `Gate::define('ability', closure|string)` in providers.
 *
 * Convention (`Post` → `PostPolicy`) is deliberately NOT resolved: if
 * the runtime mapping is not proven, the chain stays unresolved and
 * evidence degrades to medium instead of suppressing on a guess.
 */
final class PolicyRegistry implements ScanContextAware
{
    use ScanContextTrait;

    /**
     * @var array<string, array{model: string, policy: string, file: string, line: int}>
     *   lowercase model FQCN => registration
     */
    private array $policies = [];

    /**
     * @var array<string, array{ability: string, file: string, line: int, trivial: bool}>
     *   lowercase ability => definition (`trivial` = `fn () => true`)
     */
    private array $defines = [];

    /** @var list<string> */
    private array $files = [];

    /**
     * @param list<string> $files
     */
    public function build(array $files): self
    {
        $this->files = $files;
        foreach ($files as $file) {
            $base = strtolower(str_replace('\\', '/', $file));
            if (!str_ends_with($base, 'serviceprovider.php') && !str_contains($base, '/providers/')) {
                continue;
            }
            if (strtolower((string) pathinfo($file, PATHINFO_EXTENSION)) !== 'php') {
                continue;
            }
            $this->collectFromFile($file);
        }

        return $this;
    }

    /**
     * @return array<string, array{model: string, policy: string, file: string, line: int}>
     */
    public function policies(): array
    {
        return $this->policies;
    }

    /**
     * @return array{model: string, policy: string, file: string, line: int}|null
     */
    public function policyForModel(string $model): ?array
    {
        return $this->policies[strtolower(ltrim($model, '\\'))] ?? null;
    }

    /**
     * @return array{ability: string, file: string, line: int, trivial: bool}|null
     */
    public function defineForAbility(string $ability): ?array
    {
        return $this->defines[strtolower(trim($ability))] ?? null;
    }

    /**
     * Resolve one authorization call to its chain. Three outcomes:
     * - resolved/high: ability + model → registered policy → method exists.
     * - ability-only/medium: Gate::define() proves the ability, no model.
     * - unresolved/medium: the call exists but nothing is proven (dynamic
     *   ability, unknown model, unregistered mapping). Never a guess —
     *   unresolved is evidence of a check, not of protection by proof.
     *
     * @return array{status: string, ability: string|null, model: string|null, policy: string|null, method: string|null, source: string|null, confidence: string}
     */
    public function resolveAuthorizeCall(?string $ability, ?string $model): array
    {
        if ($ability !== null && $model !== null) {
            $chain = $this->policyChain($ability, $model);
            if ($chain !== null) {
                return [
                    'status' => 'resolved',
                    'ability' => $ability,
                    'model' => $model,
                    'policy' => $chain['policy'],
                    'method' => $chain['method'],
                    'source' => $chain['source'],
                    'confidence' => 'high',
                ];
            }
        }
        if ($ability !== null) {
            $define = $this->defineForAbility($ability);
            if ($define !== null && !$define['trivial']) {
                return [
                    'status' => 'ability-only',
                    'ability' => $ability,
                    'model' => $model,
                    'policy' => null,
                    'method' => null,
                    'source' => $define['file'] . ':' . $define['line'],
                    'confidence' => 'medium',
                ];
            }
        }

        return [
            'status' => 'unresolved',
            'ability' => $ability,
            'model' => $model,
            'policy' => null,
            'method' => null,
            'source' => null,
            'confidence' => 'medium',
        ];
    }

    /**
     * Full chain: model → registered policy → policy method. The method
     * only needs to exist — the framework enforces its boolean, so no
     * body analysis is required (unlike middleware gates).
     *
     * @return array{model: string, policy: string, policy_file: string, method: string, source: string}|null
     */
    public function policyChain(string $ability, string $model): ?array
    {
        $registration = $this->policyForModel($model);
        if ($registration === null) {
            return null;
        }
        $file = $this->policyFile($registration['policy']);
        if ($file === null) {
            return null;
        }
        $method = $this->policyMethod($file, $ability);
        if ($method === null) {
            return null;
        }

        return [
            'model' => $registration['model'],
            'policy' => $registration['policy'],
            'policy_file' => $file,
            'method' => $method['name'],
            'source' => $file . ':' . $method['line'],
        ];
    }

    /**
     * @return array{name: string, line: int}|null
     */
    private function policyMethod(string $file, string $ability): ?array
    {
        $code = $this->sharedSource($file);
        if ($code === '') {
            return null;
        }
        $ast = $this->sharedAst($file);
        if ($ast === null) {
            return null;
        }
        $finder = new CountingNodeFinder();
        $methods = $finder->find($ast, static function (Node $node): bool {
            return $node instanceof Node\Stmt\ClassMethod;
        });
        $fallback = null;
        foreach ($methods as $method) {
            if (!$method instanceof Node\Stmt\ClassMethod) {
                continue;
            }
            $name = $method->name->toString();
            if ($name === $ability) {
                return ['name' => $name, 'line' => $method->getStartLine()];
            }
            if ($fallback === null && strtolower($name) === strtolower($ability)) {
                $fallback = ['name' => $name, 'line' => $method->getStartLine()];
            }
        }

        return $fallback;
    }

    /**
     * Locate the file declaring a policy class by `*Policy/<Short>.php`
     * convention (case-insensitive), falling back to any same-named file.
     */
    public function policyFile(string $policy): ?string
    {
        $short = $this->shortClass($policy);
        if ($short === '') {
            return null;
        }
        $fallback = null;
        foreach ($this->files as $file) {
            $normalized = str_replace('\\', '/', $file);
            if (strtolower((string) pathinfo($normalized, PATHINFO_BASENAME)) !== strtolower($short . '.php')) {
                continue;
            }
            if (str_contains(strtolower($normalized), '/policies/')) {
                return $file;
            }
            $fallback ??= $file;
        }

        return $fallback;
    }

    private function collectFromFile(string $file): void
    {
        $code = $this->sharedSource($file);
        if ($code === '') {
            return;
        }
        $ast = $this->sharedAst($file);
        if ($ast === null) {
            return;
        }
        $finder = new CountingNodeFinder();
        $uses = $this->useMap($finder, $ast);
        $namespace = $this->namespaceOf($finder, $ast);

        // protected $policies = [Model::class => Policy::class].
        $props = $finder->find($ast, static function (Node $node): bool {
            return $node instanceof Node\Stmt\Property;
        });
        foreach ($props as $prop) {
            if (!$prop instanceof Node\Stmt\Property) {
                continue;
            }
            foreach ($prop->props as $item) {
                if (
                    !$item instanceof Node\Stmt\PropertyProperty
                    || strtolower($item->name->toString()) !== 'policies'
                    || !$item->default instanceof Node\Expr\Array_
                ) {
                    continue;
                }
                $this->collectPolicyArray($item->default, $uses, $namespace, $file);
            }
        }

        // Gate::policy(A::class, B::class) / Gate::define('x', ...).
        $calls = $finder->find($ast, static function (Node $node): bool {
            return $node instanceof Node\Expr\StaticCall;
        });
        foreach ($calls as $call) {
            if (
                !$call instanceof Node\Expr\StaticCall
                || !$call->class instanceof Node\Name
                || $this->shortClass($call->class->toString()) !== 'Gate'
                || !$call->name instanceof Node\Identifier
            ) {
                continue;
            }
            $method = strtolower($call->name->toString());
            if ($method === 'policy') {
                $model = $call->args[0] ?? null;
                $policy = $call->args[1] ?? null;
                if (
                    $model instanceof Node\Arg
                    && $policy instanceof Node\Arg
                ) {
                    $this->addPolicy($model->value, $policy->value, $uses, $namespace, $file, $call->getStartLine());
                }
            } elseif ($method === 'define') {
                $ability = $call->args[0] ?? null;
                $callback = $call->args[1] ?? null;
                if (
                    $ability instanceof Node\Arg
                    && $ability->value instanceof Node\Scalar\String_
                    && $ability->value->value !== ''
                    && $callback instanceof Node\Arg
                ) {
                    $key = strtolower($ability->value->value);
                    $this->defines[$key] ??= [
                        'ability' => $ability->value->value,
                        'file' => $file,
                        'line' => $call->getStartLine(),
                        'trivial' => $this->isTrivialCallback($callback->value),
                    ];
                }
            }
        }
    }

    /**
     * @param array<string, string> $uses
     */
    private function collectPolicyArray(
        Node\Expr\Array_ $array,
        array $uses,
        ?string $namespace,
        string $file
    ): void {
        foreach ($array->items as $item) {
            if (!$item instanceof Node\Expr\ArrayItem || $item->key === null) {
                continue;
            }
            $this->addPolicy($item->key, $item->value, $uses, $namespace, $file, $item->getStartLine());
        }
    }

    /**
     * @param array<string, string> $uses
     */
    private function addPolicy(
        Node\Expr $modelExpr,
        Node\Expr $policyExpr,
        array $uses,
        ?string $namespace,
        string $file,
        int $line
    ): void {
        $model = $this->classString($modelExpr, $uses, $namespace);
        $policy = $this->classString($policyExpr, $uses, $namespace);
        if ($model === null || $policy === null) {
            return;
        }
        $this->policies[strtolower($model)] ??= [
            'model' => $model,
            'policy' => $policy,
            'file' => $file,
            'line' => $line,
        ];
    }

    /**
     * A `fn () => true` (or `true` string) callback decides nothing —
     * like FormRequest `authorize() => true`, it is not evidence.
     */
    private function isTrivialCallback(Node\Expr $expr): bool
    {
        if ($expr instanceof Node\Scalar\String_) {
            return strtolower($expr->value) === 'true';
        }
        if ($expr instanceof Node\Expr\ArrowFunction && $expr->expr instanceof Node\Expr\ConstFetch) {
            return strtolower($expr->expr->name->toString()) === 'true';
        }
        if (
            $expr instanceof Node\Expr\Closure
            && count($expr->stmts) === 1
            && $expr->stmts[0] instanceof Node\Stmt\Return_
            && $expr->stmts[0]->expr instanceof Node\Expr\ConstFetch
        ) {
            return strtolower($expr->stmts[0]->expr->name->toString()) === 'true';
        }

        return false;
    }

    /**
     * @param array<string, string> $uses
     */
    private function classString(Node\Expr $expr, array $uses, ?string $namespace): ?string
    {
        if ($expr instanceof Node\Expr\ClassConstFetch && $expr->class instanceof Node\Name) {
            if ($expr->class instanceof Node\Name\FullyQualified) {
                return $expr->class->toString();
            }

            return $this->resolveName($expr->class->toString(), $uses, $namespace);
        }
        if ($expr instanceof Node\Scalar\String_ && $expr->value !== '') {
            return ltrim($expr->value, '\\');
        }

        return null;
    }

    /**
     * @param array<string, string> $uses
     */
    private function resolveName(string $name, array $uses, ?string $namespace): string
    {
        $pos = strpos($name, '\\');
        if ($pos !== false) {
            $first = strtolower(substr($name, 0, $pos));
            if (isset($uses[$first])) {
                return $uses[$first] . substr($name, $pos);
            }

            return $namespace !== null ? $namespace . '\\' . $name : $name;
        }
        $lower = strtolower($name);
        if (isset($uses[$lower])) {
            return $uses[$lower];
        }

        return $namespace !== null ? $namespace . '\\' . $name : $name;
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
