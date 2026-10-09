<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Analyzers\Ops;

use Rampart\QualityChecker\Result\Confidence;
use Rampart\QualityChecker\Result\Issue;
use Rampart\QualityChecker\Result\Severity;
use Rampart\QualityChecker\Scanning\ScanContextAware;
use Rampart\QualityChecker\Scanning\ScanContextTrait;

final class EolAnalyzer implements ScanContextAware
{
    use ScanContextTrait;

    private const RULE = 'EOL_COMPONENT';

    private const EOL_DATES = [
        'laravel/framework' => '2026-08-10', // Laravel 10 EOL example, update with endoflife.date
        'php' => '2026-11-26', // PHP 8.1 EOL
    ];

    /**
     * @param list<string> $files
     * @return list<Issue>
     */
    public function analyze(array $files): array
    {
        $root = $this->scanRoot();
        if ($root === null) {
            return [];
        }
        $composer = $root . DIRECTORY_SEPARATOR . 'composer.json';
        if (!is_file($composer)) {
            return [];
        }
        $code = $this->sharedSource($composer);
        if ($code === '') {
            return [];
        }
        $data = json_decode($code, true);
        if (!is_array($data)) {
            return [];
        }
        $issues = [];
        $requires = $data['require'] ?? [];
        if (!is_array($requires)) {
            return [];
        }
        foreach (['laravel/framework', 'php'] as $pkg) {
            $constraint = $requires[$pkg] ?? null;
            if (!is_string($constraint)) {
                continue;
            }
            $eol = self::EOL_DATES[$pkg];
            if (strtotime($eol) < time()) {
                $issues[] = new Issue(
                    self::RULE,
                    sprintf('%s %s is end-of-life since %s — upgrade.', $pkg, $constraint, $eol),
                    $composer,
                    1,
                    Severity::Warning,
                    'custom',
                    ['package' => $pkg, 'constraint' => $constraint, 'eol' => $eol],
                    Confidence::Medium
                );
            }
        }

        return $issues;
    }
}
