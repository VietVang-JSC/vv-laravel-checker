<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Reporters;

use Rampart\QualityChecker\Result\CheckResult;
use Rampart\QualityChecker\Runner\CheckContext;

interface ReporterInterface
{
    /**
     * @param CheckResult[] $results
     */
    public function render(array $results, CheckContext $ctx): void;
}
