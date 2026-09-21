<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Analyzers\Convention;

use VietVang\QualityChecker\Result\Confidence;
use VietVang\QualityChecker\Result\Issue;
use VietVang\QualityChecker\Result\Severity;

final class TodoFixmeAnalyzer
{
    private const RULE = 'TODO_FIXME';

    private const PATTERN = '/(TODO|FIXME|HACK|XXX)/i';

    public function analyze(array $files): array
    {
        $issues = [];
        foreach ($files as $file) {
            if (!$this->supports($file)) {
                continue;
            }
            foreach ($this->analyzeFile($file) as $issue) {
                $issues[] = $issue;
            }
        }

        return $issues;
    }

    public function supports(string $path): bool
    {
        return strtolower((string) pathinfo($path, PATHINFO_EXTENSION)) === 'php';
    }

    private function analyzeFile(string $file): array
    {
        $code = $this->readFile($file);
        if ($code === '') {
            return [];
        }

        $issues = [];
        $lines = preg_split('/\r\n|\r|\n/', $code) ?: [];

        foreach ($lines as $index => $line) {
            if (!$this->isCommentLine($line)) {
                continue;
            }
            if (preg_match(self::PATTERN, $line, $m) !== 1) {
                continue;
            }

            $issues[] = new Issue(
                self::RULE,
                sprintf('Marked with "%s" comment: %s', strtoupper($m[1]), trim($line)),
                $file,
                $index + 1,
                Severity::Info,
                'custom',
                ['marker' => strtoupper($m[1])],
                Confidence::Low
            );
        }

        return $issues;
    }

    private function isCommentLine(string $line): bool
    {
        $trimmed = ltrim($line);

        if (str_starts_with($trimmed, '//') || str_starts_with($trimmed, '#')) {
            return true;
        }

        return str_starts_with($trimmed, '/*');
    }

    private function readFile(string $path): string
    {
        if (!is_file($path)) {
            return '';
        }

        return (string) file_get_contents($path);
    }
}
