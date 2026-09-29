<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Semantic;

use PhpParser\Node;
use Rampart\QualityChecker\Scanning\ScanContextAware;
use Rampart\QualityChecker\Scanning\ScanContextTrait;

/**
 * Tier 1 middleware resolution: alias → middleware class. Symbol
 * resolution only — it never concludes anything is protected.
 *
 * Sources understood (Laravel ≤10 and 11+):
 * - `*Http\Kernel::$routeMiddleware` / `$middlewareAliases` properties
 *   (`'admin' => AdminMiddleware::class`, string or `::class` values).
 * - `bootstrap/app.php` style `$middleware->alias(['admin' => ...])`.
 *
 * Alias lookup is by base name (`authorize:superuser` looks up
 * `authorize`); the `:parameter` travels with the route, not the alias.
 */
final class MiddlewareRegistry implements ScanContextAware
{
    use ScanContextTrait;

    /**
     * @var array<string, array{class: string, file: string, line: int|null}>
     *   lowercase alias => registration
     */
    private array $aliases = [];

    /** @var list<string> */
    private array $files = [];

    /**
     * @param list<string> $files
     */
    public function build(array $files): self
    {
        $this->files = $files;
        foreach ($files as $file) {
            if (!$this->isKernelFile($file) && !$this->isAppBootstrap($file)) {
                continue;
            }
            $this->collectFromFile($file);
        }

        return $this;
    }

    /**
     * @return array{class: string, file: string, line: int|null}|null
     */
    public function resolve(string $alias): ?array
    {
        $base = strtolower(trim(explode(':', $alias, 2)[0]));

        return $base === '' ? null : ($this->aliases[$base] ?? null);
    }

    /**
     * @return array<string, array{class: string, file: string, line: int|null}>
     */
    public function aliases(): array
    {
        return $this->aliases;
    }

    /**
     * Locate the file declaring a middleware class without parsing the
     * world: middleware live in `*Middleware/<Short>.php` by convention
     * (case-insensitive — Linkstack ships `Middleware/admin.php`). Falls
     * back to any same-short-name PHP file under the scanned roots.
     */
    public function classFile(string $class): ?string
    {
        $short = $this->shortClass($class);
        if ($short === '') {
            return null;
        }
        $fallback = null;
        foreach ($this->files as $file) {
            $normalized = str_replace('\\', '/', $file);
            if (strtolower((string) pathinfo($normalized, PATHINFO_BASENAME)) !== strtolower($short . '.php')) {
                continue;
            }
            if (str_contains(strtolower($normalized), '/middleware/')) {
                return $file;
            }
            $fallback ??= $file;
        }

        return $fallback;
    }

    private function isKernelFile(string $file): bool
    {
        $normalized = str_replace('\\', '/', $file);

        return str_ends_with($normalized, 'Http/Kernel.php')
            || str_ends_with($normalized, 'Http\\Kernel.php');
    }

    private function isAppBootstrap(string $file): bool
    {
        $normalized = str_replace('\\', '/', $file);

        return str_ends_with($normalized, 'bootstrap/app.php');
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
        $finder = new \PhpParser\NodeFinder();
        $uses = $this->useMap($finder, $ast);
        $namespace = $this->namespaceOf($finder, $ast);

        // Kernel::$routeMiddleware / $middlewareAliases array properties.
        $props = $finder->find($ast, static function (Node $node): bool {
            return $node instanceof Node\Stmt\Property;
        });
        foreach ($props as $prop) {
            if (!$prop instanceof Node\Stmt\Property || $prop->props === []) {
                continue;
            }
            $name = strtolower($prop->props[0]->name->toString());
            if ($name !== 'routemiddleware' && $name !== 'middlewarealiases') {
                continue;
            }
            $default = $prop->props[0]->default;
            if ($default instanceof Node\Expr\Array_) {
                $this->collectAliasArray($default, $uses, $namespace, $file);
            }
        }

        // bootstrap/app.php: $middleware->alias([...]).
        $calls = $finder->find($ast, static function (Node $node): bool {
            return $node instanceof Node\Expr\MethodCall;
        });
        foreach ($calls as $call) {
            if (
                !$call instanceof Node\Expr\MethodCall
                || !$call->name instanceof Node\Identifier
                || strtolower($call->name->toString()) !== 'alias'
            ) {
                continue;
            }
            $arg = $call->args[0] ?? null;
            if ($arg instanceof Node\Arg && $arg->value instanceof Node\Expr\Array_) {
                $this->collectAliasArray($arg->value, $uses, $namespace, $file);
            }
        }
    }

    /**
     * @param array<string, string> $uses
     */
    private function collectAliasArray(
        Node\Expr\Array_ $array,
        array $uses,
        ?string $namespace,
        string $file
    ): void {
        foreach ($array->items as $item) {
            if (
                !$item instanceof Node\Expr\ArrayItem
                || !$item->key instanceof Node\Scalar\String_
                || strtolower(trim($item->key->value)) === ''
            ) {
                continue;
            }
            $class = $this->classString($item->value, $uses, $namespace);
            if ($class === null) {
                continue;
            }
            $alias = strtolower(trim($item->key->value));
            $this->aliases[$alias] ??= [
                'class' => $class,
                'file' => $file,
                'line' => $item->getStartLine(),
            ];
        }
    }

    /**
     * @param array<string, string> $uses
     */
    private function classString(Node\Expr $expr, array $uses, ?string $namespace): ?string
    {
        if ($expr instanceof Node\Expr\ClassConstFetch && $expr->class instanceof Node\Name) {
            // FullyQualified::toString() drops the leading backslash, so
            // detect FQ names structurally instead of by string prefix.
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
        if (str_starts_with($name, '\\')) {
            return ltrim($name, '\\');
        }
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
    private function useMap(\PhpParser\NodeFinder $finder, array $nodes): array
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
    private function namespaceOf(\PhpParser\NodeFinder $finder, array $nodes): ?string
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
