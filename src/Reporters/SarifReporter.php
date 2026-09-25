<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Reporters;

use VietVang\QualityChecker\Result\CheckResult;
use VietVang\QualityChecker\Result\Issue;
use VietVang\QualityChecker\Result\Severity;
use VietVang\QualityChecker\Remediation\RuleRemediation;
use VietVang\QualityChecker\Runner\CheckContext;

/**
 * SARIF 2.1.0 reporter for GitHub Advanced Security / code scanning upload.
 *
 * @see https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning
 */
final class SarifReporter implements ReporterInterface
{
    private const LEVEL_MAP = [
        'critical' => 'error',
        'error' => 'error',
        'warning' => 'warning',
        'info' => 'note',
    ];

    private const SEVERITY_RANK = [
        'info' => 1,
        'warning' => 2,
        'error' => 3,
        'critical' => 4,
    ];

    public function render(array $results, CheckContext $ctx): void
    {
        $rules = [];
        $sarifResults = [];

        foreach ($results as $result) {
            if (!$result instanceof CheckResult) {
                continue;
            }
            foreach ($result->issues as $issue) {
                if (!$issue instanceof Issue) {
                    continue;
                }

                $this->registerRule($rules, $issue, $ctx);
                $sarifResults[] = $this->buildResult($issue, $ctx->basePath);
            }
        }

        $payload = [
            '$schema' => 'https://json.schemastore.org/sarif-2.1.0.json',
            'version' => '2.1.0',
            'runs' => [
                [
                    'tool' => [
                        'driver' => [
                            'name' => 'vietvang/quality-checker',
                            'informationUri' => 'https://github.com/VietVang-JSC/vv-laravel-checker',
                            'version' => $ctx->packageVersion,
                            'rules' => array_values($rules),
                        ],
                    ],
                    'results' => $sarifResults,
                    'properties' => [
                        'tier' => $ctx->tier,
                        'fail_on' => $ctx->failOn,
                        'min_confidence' => $ctx->minConfidence,
                        'exit_code' => $ctx->exitCode,
                    ],
                ],
            ],
        ];

        if (!is_dir($ctx->outputDir) && !@mkdir($ctx->outputDir, 0777, true) && !is_dir($ctx->outputDir)) {
            return;
        }

        file_put_contents(
            $ctx->outputDir . DIRECTORY_SEPARATOR . 'quality-report.sarif',
            json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . PHP_EOL
        );
    }

    /**
     * @param array<string, array<string, mixed>> $rules
     */
    private function registerRule(array &$rules, Issue $issue, CheckContext $ctx): void
    {
        $id = $issue->rule;
        $severity = $issue->severity->value;

        if (isset($rules[$id])) {
            $currentRank = self::SEVERITY_RANK[$severity];
            $existingRank = self::SEVERITY_RANK[$rules[$id]['_severity']] ?? 1;
            if ($currentRank > $existingRank) {
                $rules[$id]['defaultConfiguration']['level'] = self::LEVEL_MAP[$severity];
                $rules[$id]['_severity'] = $severity;
            }

            return;
        }

        $descriptor = [
            'id' => $id,
            'name' => str_replace('-', '_', $id),
            'shortDescription' => [
                'text' => $this->shortDescription($issue),
            ],
            'defaultConfiguration' => [
                'level' => self::LEVEL_MAP[$severity],
            ],
            'properties' => [
                'tags' => $this->tags($issue),
                'confidence' => $issue->confidence->value,
                'source' => $issue->source,
            ],
            '_severity' => $severity,
        ];

        $help = RuleRemediation::helpMarkdown($id);
        if ($help !== null) {
            $descriptor['help'] = ['text' => $help];
            $helpUri = $this->helpUri($id, $ctx);
            if ($helpUri !== null) {
                $descriptor['helpUri'] = $helpUri;
            }
        }

        $rules[$id] = $descriptor;
    }

    private function helpUri(string $rule, CheckContext $ctx): ?string
    {
        $entry = RuleRemediation::for($rule);
        $anchor = $entry['docs'] ?? null;
        if ($anchor === null) {
            return null;
        }

        $cfg = $ctx->configFor('html');
        $repo = rtrim(trim((string) ($cfg['repo_url'] ?? '')), '/');
        if ($repo === '') {
            $repo = 'https://github.com/VietVang-JSC/vv-laravel-checker';
        }
        $branch = trim((string) ($cfg['branch'] ?? 'main'));
        if ($branch === '') {
            $branch = 'main';
        }

        return $repo . '/blob/' . $branch . '/docs/false-positives.md' . $anchor;
    }

    /**
     * @return array<string, mixed>
     */
    private function buildResult(Issue $issue, string $basePath): array
    {
        $result = [
            'ruleId' => $issue->rule,
            'level' => self::LEVEL_MAP[$issue->severity->value],
            'message' => [
                'text' => $issue->message,
            ],
        ];

        if ($issue->file !== null) {
            $result['locations'] = [
                [
                    'physicalLocation' => [
                        'artifactLocation' => [
                            'uri' => $this->relativeUri($issue->file, $basePath),
                        ],
                        'region' => array_filter([
                            'startLine' => $issue->line ?? 1,
                        ]),
                    ],
                ],
            ];
        }

        $result['properties'] = [
            'confidence' => $issue->confidence->value,
            'checker' => $issue->source,
        ];

        return $result;
    }

    private function relativeUri(string $file, string $basePath): string
    {
        $normalizedBase = rtrim(str_replace('\\', '/', $basePath), '/');
        $normalizedFile = str_replace('\\', '/', $file);

        if (str_starts_with($normalizedFile, $normalizedBase . '/')) {
            $normalizedFile = substr($normalizedFile, strlen($normalizedBase) + 1);
        }

        return ltrim($normalizedFile, '/');
    }

    private function shortDescription(Issue $issue): string
    {
        $message = str_replace(["\r", "\n"], ' ', $issue->message);

        return $issue->rule . ': ' . (strlen($message) > 100 ? substr($message, 0, 97) . '...' : $message);
    }

    /**
     * @return list<string>
     */
    private function tags(Issue $issue): array
    {
        $tags = ['quality-checker', $issue->source, 'severity:' . $issue->severity->value];

        if (str_starts_with($issue->rule, 'OWASP_')) {
            $tags[] = 'owasp';
            $tags[] = 'security';
        }
        if (str_starts_with($issue->rule, 'TAINT_')) {
            $tags[] = 'taint';
            $tags[] = 'security';
        }
        if (in_array($issue->rule, ['SQL_INJECTION', 'UNSAFE_EVAL', 'HARDCODED_SECRET'], true)) {
            $tags[] = 'security';
        }

        return array_values(array_unique($tags));
    }
}
