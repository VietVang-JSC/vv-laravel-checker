<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Semantic;

use PhpParser\Node;
use PhpParser\NodeFinder;

/**
 * Resolving PHP class names the way PHP itself does.
 *
 * Route files name controllers as short strings (`'UserController'`) or as
 * `UserController::class`, and both only mean something once the file's
 * `use` imports and `namespace` declaration are applied. That logic was
 * inlined in LaravelSemanticIndex, which made a 1300-line route walker also
 * the owner of PHP name resolution. It is pure and stateless, so it lives
 * here and is shared.
 *
 * Everything here is deliberately conservative: an unresolvable name returns
 * null / the input unchanged rather than a guess, because a wrong FQCN would
 * silently attach the wrong middleware and authorization evidence to a route.
 */
final class PhpNameResolver
{
    /**
     * Route files are recognised by directory (`routes/`) or by the
     * conventional entrypoint names.
     */
    public static function isRouteFile(string $file): bool
    {
        $normalized = str_replace('\\', '/', $file);
        if (str_contains($normalized, '/routes/') || str_contains($normalized, '/Routes/')) {
            return true;
        }

        $base = strtolower((string) pathinfo($normalized, PATHINFO_BASENAME));

        return $base === 'web.php' || $base === 'api.php';
    }

    public static function isAbsolutePath(string $path): bool
    {
        return str_starts_with($path, '/')
            || str_starts_with($path, '\\')
            || (bool) preg_match('#^[A-Za-z]:[\\\\/]#', $path);
    }

    /**
     * Resolve a written name to its fully-qualified form.
     *
     * @param array<string, string> $uses lowercase alias => FQCN
     */
    public static function resolveName(string $name, array $uses, ?string $namespace): string
    {
        if (str_starts_with($name, '\\')) {
            return ltrim($name, '\\');
        }

        $pos = strpos($name, '\\');
        if ($pos !== false) {
            $first = strtolower(substr($name, 0, $pos));
            $rest = substr($name, $pos);
            if (isset($uses[$first])) {
                return $uses[$first] . $rest;
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
     * Class name behind `Foo::class` or a `'Foo'` string literal.
     *
     * @param array<string, string> $uses
     */
    public static function classItemName(Node\Expr $expr, array $uses, ?string $namespace): ?string
    {
        if ($expr instanceof Node\Expr\ClassConstFetch && $expr->class instanceof Node\Name) {
            return self::resolveName($expr->class->toString(), $uses, $namespace);
        }

        if ($expr instanceof Node\Scalar\String_ && $expr->value !== '') {
            return self::resolveName($expr->value, $uses, $namespace);
        }

        return null;
    }

    /**
     * `use` imports of a file, keyed by lowercase alias.
     *
     * @param list<Node> $nodes
     * @return array<string, string>
     */
    public static function useMap(array $nodes, NodeFinder $finder): array
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
    public static function namespaceOf(array $nodes, NodeFinder $finder): ?string
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

    /**
     * @param array<mixed> $nodes
     * @return list<Node>
     */
    public static function nodeList(array $nodes): array
    {
        $out = [];
        foreach ($nodes as $node) {
            if ($node instanceof Node) {
                $out[] = $node;
            }
        }

        return $out;
    }

    /**
     * Trailing segment of a class name, for comparing against short
     * references such as `Route` or `RouteServiceProvider`.
     */
    public static function shortClass(string $class): string
    {
        $trimmed = ltrim($class, '\\');
        $pos = strrpos($trimmed, '\\');

        return $pos === false ? $trimmed : substr($trimmed, $pos + 1);
    }
}
