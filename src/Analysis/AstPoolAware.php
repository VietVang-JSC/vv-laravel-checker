<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Analysis;

/**
 * Opt-in shared AST parsing. Analyzers implementing this interface receive
 * the run-wide AstPool instead of parsing files themselves.
 */
interface AstPoolAware
{
    public function setAstPool(AstPool $pool): void;
}
