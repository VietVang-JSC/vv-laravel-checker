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

    private function shared(): ScanContext
    {
        return $this->scanContext ??= new ScanContext();
    }
}
