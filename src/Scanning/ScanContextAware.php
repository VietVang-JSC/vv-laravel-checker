<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Scanning;

/**
 * Analyzers opting into shared source/AST. The checker injects one
 * ScanContext per run; analyzers without an injected context fall back
 * to a private instance (same results, no cross-analyzer sharing), so
 * unit tests keep calling analyze() directly.
 */
interface ScanContextAware
{
    public function setScanContext(ScanContext $context): void;
}
