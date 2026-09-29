<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Analysis;

use PhpParser\Node;
use PhpParser\NodeVisitorAbstract;

/**
 * Census visitor (PERF-EVAL-2): counts nodes during the single
 * canonical linker traversal in ScanContext::ast(). Shares the walk
 * with ParentConnectingVisitor — zero extra traversals.
 */
final class NodeCountVisitor extends NodeVisitorAbstract
{
    public int $count = 0;

    /**
     * @return null (never replaces or removes nodes)
     */
    public function enterNode(Node $node)
    {
        ++$this->count;

        return null;
    }
}
