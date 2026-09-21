<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Reporters;

use VietVang\QualityChecker\Result\CheckResult;
use VietVang\QualityChecker\Runner\CheckContext;

interface ReporterInterface
{
    /**
     * @param CheckResult[] $results
     */
    public function render(array $results, CheckContext $ctx): void;
}
