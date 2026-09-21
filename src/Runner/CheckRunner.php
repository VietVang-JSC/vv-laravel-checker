<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Runner;

use VietVang\QualityChecker\Checkers\CheckerInterface;
use VietVang\QualityChecker\Checkers\ComposerAuditChecker;
use VietVang\QualityChecker\Checkers\CustomAnalyzerChecker;
use VietVang\QualityChecker\Checkers\PhpcsChecker;
use VietVang\QualityChecker\Checkers\PhpstanChecker;
use VietVang\QualityChecker\Checkers\PhpunitChecker;
use VietVang\QualityChecker\Checkers\TrivyChecker;
use VietVang\QualityChecker\Result\CheckResult;
use VietVang\QualityChecker\Result\Confidence;
use VietVang\QualityChecker\Result\Issue;
use VietVang\QualityChecker\Result\Severity;
use VietVang\QualityChecker\Tools\ToolInstaller;

final class CheckRunner
{
    private CheckContext $ctx;

    public function __construct(CheckContext $ctx)
    {
        $this->ctx = $ctx;
    }

    /**
     * @return CheckerInterface[]
     */
    public function buildCheckers(): array
    {
        $checkers = [
            new PhpcsChecker(),
            new PhpstanChecker(),
            new PhpunitChecker(),
            new ComposerAuditChecker(),
            new TrivyChecker(),
            new CustomAnalyzerChecker(),
        ];

        $only = $this->ctx->only;
        $exclude = $this->ctx->exclude;

        if (count($only) === 0 && count($exclude) === 0) {
            return $checkers;
        }

        return array_values(array_filter($checkers, function (CheckerInterface $checker) use ($only, $exclude): bool {
            if (count($only) > 0 && !in_array($checker->name(), $only, true)) {
                return false;
            }

            return !in_array($checker->name(), $exclude, true);
        }));
    }

    /**
     * Run all checkers sequentially (cache-aware).
     *
     * @param CheckerInterface[] $checkers
     * @return CheckResult[]
     */
    public function run(array $checkers): array
    {
        $cache = new ResultCache($this->ctx);
        $results = [];

        foreach ($checkers as $checker) {
            if (!$checker->isAvailable($this->ctx)) {
                $skipped = $this->tryProvision($checker);
                $results[] = $skipped;
                continue;
            }

            $cacheKey = $cache->key($checker->name(), $this->ctx->paths, $checker->config());

            if (!$this->ctx->noCache) {
                $cached = $cache->get($cacheKey);
                if (is_array($cached)) {
                    $results[] = CheckResult::fromArray($cached);
                    continue;
                }
            }

            $result = $checker->run($this->ctx);
            $cache->put($cacheKey, $result->toArray(), 3600);
            $results[] = $result;
        }

        return $results;
    }

    /**
     * Try to self-provision a missing tool; if it becomes available, run the
     * checker for real. Otherwise return a 'skipped' result with an install hint.
     */
    private function tryProvision(CheckerInterface $checker): CheckResult
    {
        $installer = new ToolInstaller($this->ctx);

        if ($installer->canInstall($checker->name())) {
            $installed = $installer->install($checker->name());
            if ($installed && $checker->isAvailable($this->ctx)) {
                return $checker->run($this->ctx);
            }

            return new CheckResult(
                $checker->name(),
                'skipped',
                0.0,
                [],
                null,
                sprintf(
                    '%s — tool is missing and could not be auto-installed. Install manually: %s',
                    $checker->description(),
                    $installer->hint($checker->name())
                )
            );
        }

        return new CheckResult(
            $checker->name(),
            'skipped',
            0.0,
            [],
            null,
            sprintf('%s — tool not available in this project.', $checker->description())
        );
    }

    /**
     * @param CheckResult[] $results
     */
    public function shouldFail(array $results): bool
    {
        if (strtolower($this->ctx->failOn) === 'none') {
            return false;
        }

        $threshold = Severity::fromString($this->ctx->failOn)->intValue();
        $minConfidence = Confidence::fromString($this->ctx->minConfidence)->intValue();

        foreach ($results as $result) {
            foreach ($result->issues as $issue) {
                if (!$issue instanceof Issue) {
                    continue;
                }

                // Only high-confidence issues can fail the gate at the 'security' tier.
                if (
                    $this->ctx->tier === 'security'
                    && $issue->source !== 'composer_audit'
                    && $issue->confidence->intValue() < Confidence::High->intValue()
                ) {
                    continue;
                }

                if ($issue->confidence->intValue() < $minConfidence) {
                    continue;
                }

                if ($issue->severity->intValue() >= $threshold) {
                    return true;
                }
            }
        }

        return false;
    }
}
