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

    /**
     * Root of the project being scanned.
     *
     * Prefers the path the checker recorded, so an analyzer resolves
     * `routes/` and `tests/Feature/` against the target project rather than
     * against whatever directory the process happens to be in. Falls back to
     * getcwd() only for the direct-analyze() calls unit tests make, where no
     * checker ran and there is nothing better to go on.
     */
    protected function scanRoot(): ?string
    {
        $root = $this->shared()->basePath();
        if ($root !== null) {
            return $root;
        }

        $cwd = getcwd();

        return is_string($cwd) ? $cwd : null;
    }

    private function shared(): ScanContext
    {
        return $this->scanContext ??= new ScanContext();
    }
}
