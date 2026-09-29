<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Scanning;

/**
 * Default ScanContextAware implementation: injected shared context per
 * run, private fallback otherwise (same results, no cross-analyzer
 * sharing) so unit tests keep calling analyze() directly.
 */
trait ScanContextTrait
{
    private ?ScanContext $scanContext = null;

    public function setScanContext(ScanContext $context): void
    {
        $this->scanContext = $context;
    }

    protected function sharedSource(string $file): string
    {
        return $this->shared()->source($file);
    }

    /**
     * @return list<\PhpParser\Node>|null
     */
    protected function sharedAst(string $file): ?array
    {
        return $this->shared()->ast($file);
    }

    /**
     * The run's ScanContext for hand-off to collaborators (semantic
     * indexes, helpers) that cannot receive checker injection directly.
     * Same instance the analyzer itself reads through above.
     */
    protected function sharedScanContext(): ScanContext
    {
        return $this->shared();
    }

    private function shared(): ScanContext
    {
        return $this->scanContext ??= new ScanContext();
    }
}
