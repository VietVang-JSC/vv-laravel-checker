<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Checkers;

use VietVang\QualityChecker\Result\CheckResult;
use VietVang\QualityChecker\Runner\CheckContext;

interface CheckerInterface
{
    public function name(): string;

    public function description(): string;

    public function isAvailable(CheckContext $ctx): bool;

    public function run(CheckContext $ctx): CheckResult;

    public function config(): array;
}
