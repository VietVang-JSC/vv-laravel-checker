<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Checkers;

use Rampart\QualityChecker\Result\CheckResult;
use Rampart\QualityChecker\Runner\CheckContext;

interface CheckerInterface
{
    public function name(): string;

    public function description(): string;

    public function isAvailable(CheckContext $ctx): bool;

    public function run(CheckContext $ctx): CheckResult;

    /**
     * @return array<string, mixed>
     */
    public function config(): array;
}
