<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Fixer;

/**
 * Value object describing the outcome of an auto-fix run.
 */
final class FixResult
{
    /**
     * @param int $filesFixed Number of files the fixer reported as fixed.
     * @param list<string> $errors Human-readable failure messages, if any.
     * @param string $output Raw output captured from the underlying tool.
     */
    public function __construct(
        public readonly int $filesFixed,
        public readonly array $errors,
        public readonly string $output,
    ) {
    }

    /**
     * True when no errors were encountered.
     */
    public function success(): bool
    {
        return count($this->errors) === 0;
    }
}
