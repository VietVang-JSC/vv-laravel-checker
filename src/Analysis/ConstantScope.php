<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Analysis;

use PhpParser\Node;
use PhpParser\NodeFinder;

/**
 * Resolution scope for constant expressions: one file's AST, one
 * function id (0 = top-level), and the name context for `Foo::class`.
 * Closures never open a scope — nodes inside them belong to the
 * enclosing function, matching PHP execution.
 */
final class ConstantScope
{
    /**
     * @param list<Node> $nodes file AST statements
     * @param array<string, string> $uses lowercase alias => FQCN
     */
    public function __construct(
        public readonly array $nodes,
        public readonly int $funcId,
        public readonly string $file,
        public readonly array $uses,
        public readonly ?string $namespace,
    ) {
    }

    /**
     * @param list<Node> $nodes
     */
    public static function forFile(array $nodes, string $file): self
    {
        $finder = new NodeFinder();

        return new self($nodes, 0, $file, self::useMap($finder, $nodes), self::namespaceOf($finder, $nodes));
    }

    public function forNode(Node $node): self
    {
        $funcId = (new ScopeResolver())->funcId($node, $this->nodes);

        return new self($this->nodes, $funcId, $this->file, $this->uses, $this->namespace);
    }

    /**
     * @param list<Node> $nodes
     * @return array<string, string>
     */
    private static function useMap(NodeFinder $finder, array $nodes): array
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
    private static function namespaceOf(NodeFinder $finder, array $nodes): ?string
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
}
