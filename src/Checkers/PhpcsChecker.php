<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Checkers;

use Rampart\QualityChecker\Result\CheckResult;
use Rampart\QualityChecker\Result\Issue;
use Rampart\QualityChecker\Result\Severity;
use Rampart\QualityChecker\Runner\CheckContext;

final class PhpcsChecker extends AbstractProcessChecker
{
    public function name(): string
    {
        return 'phpcs';
    }

    public function description(): string
    {
        return 'PHP_CodeSniffer — coding standard violations.';
    }

    public function config(): array
    {
        return [
            'standard' => 'PSR12',
            'severity' => 0,
        ];
    }

    public function isAvailable(CheckContext $ctx): bool
    {
        return $this->binary('vendor/bin/phpcs', $ctx) !== null;
    }

    public function run(CheckContext $ctx): CheckResult
    {
        $start = microtime(true);
        $config = $ctx->configFor('phpcs', $this->config());
        $binary = $this->binary('vendor/bin/phpcs', $ctx);

        if ($binary === null) {
            return $this->result(
                $this->name(),
                $start,
                'skipped',
                [],
                null,
                'phpcs not found. Install it with: composer require --dev squizlabs/php_codesniffer'
            );
        }

        $standard = (string) ($config['standard'] ?? 'PSR12');
        $command = $this->buildCommand($binary, $ctx, $standard, $config);

        [$exitCode, $stdout, $stderr] = $this->runProcess($command, $ctx->basePath);

        $issues = $this->parseOutput($stdout, (int) ($config['severity'] ?? 0));
        $rawOutput = trim($stdout . "\n" . $stderr);

        if ($exitCode !== 0 && count($issues) === 0) {
            $summary = sprintf(
                'phpcs exited with code %d and produced no report. The tool may have failed to run (exit %d).',
                $exitCode,
                $exitCode
            );

            return $this->result($this->name(), $start, 'error', [], $rawOutput, $summary);
        }

        $status = count($issues) > 0 ? 'failed' : 'passed';
        $summary = sprintf('phpcs found %d error(s)/warning(s).', count($issues));

        return $this->result($this->name(), $start, $status, $issues, $rawOutput, $summary);
    }

    /**
     * Build the phpcs argv.
 *
     * Blade templates are excluded here. phpcs has no extension filter, so a
 * scan path containing `resources/views` makes it report every template as
 * `Internal.NoCodeFound` and `Internal.LineEndings.Mixed` — noise on every
 * template of every Laravel app, produced on the first run. The custom checker
 * keeps blade out of its own collectors for the same reason; this applies the
 * same exclusion at the linting layer, because phpcs is handed the raw scan
 * paths and cannot filter them itself.
 *
 * The exclusion is appended to the project's own ignores rather than replacing
 * them: a team that excluded generated code must not silently start seeing it
 * again because this package added a default.
 *
 * @param array<string, mixed> $config
 * @return list<string>
 */
    private function buildCommand(string $binary, CheckContext $ctx, string $standard, array $config): array
    {
        $arguments = ['--report=json'];

        foreach (array_merge(['*.blade.php'], $this->configuredIgnores($config)) as $pattern) {
            $arguments[] = '--ignore=' . $pattern;
        }

        // A project standard wins over ours, as it did before this was extracted:
        // phpcs.xml.dist in the target is the authority on what its code looks
        // like, and passing --standard as well would override it.
        if (!$this->hasProjectStandard($ctx)) {
            array_unshift($arguments, '--standard=' . $standard);
        }

        return [$binary, ...$arguments, ...$ctx->paths];
    }

    /**
     * Patterns the project asked phpcs to skip.
     *
     * @param array<string, mixed> $config
     * @return list<string>
     */
    private function configuredIgnores(array $config): array
    {
        $raw = $config['ignore'] ?? [];
        if (is_string($raw)) {
            $raw = array_map('trim', explode(',', $raw));
        }
        if (!is_array($raw)) {
            return [];
        }

        return array_values(array_filter($raw, 'is_string'));
    }

    private function hasProjectStandard(CheckContext $ctx): bool
    {
        foreach (['phpcs.xml', 'phpcs.xml.dist', 'phpcs.dist.xml'] as $file) {
            if (is_file($ctx->basePath . DIRECTORY_SEPARATOR . $file)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Parse `phpcs --report=json`.
     *
     * The contract is `totals` + `files[<path>].messages[]`, each message carrying
     * `message`, `source`, `severity`, `type`, `line` and `column`. That shape is
     * the same in phpcs 3.x and 4.x — verified against both by running the
     * checker against each, not by assumption — so this parser deliberately
     * tolerates absent keys rather than asserting them: a future phpcs that
     * drops or renames a field should degrade to fewer issues here and be caught
     * by PhpcsJsonContractTest, not fatal in a consumer's build.
     *
     * What does change between majors is *content*, not shape: phpcs 4's PSR12
     * ruleset additionally reports `Squiz.*` codes. Same source file, more
     * findings — a tool change, not a code change.
     *
     * @return list<Issue>
     */
    private function parseOutput(string $json, int $threshold): array
    {
        $issues = [];
        $decoded = json_decode($json, true);
        if (!is_array($decoded)) {
            return $issues;
        }

        foreach (($decoded['files'] ?? []) as $file => $report) {
            if (!is_array($report)) {
                continue;
            }

            foreach (($report['messages'] ?? []) as $message) {
                if (!is_array($message)) {
                    continue;
                }

                $severity = (int) ($message['severity'] ?? 0);
                if ($threshold > 0 && $severity < $threshold) {
                    continue;
                }

                $type = (string) ($message['type'] ?? 'ERROR');
                $issues[] = new Issue(
                    (string) ($message['source'] ?? 'PHPCS'),
                    (string) ($message['message'] ?? ''),
                    $file,
                    (int) ($message['line'] ?? 0) > 0 ? (int) $message['line'] : null,
                    strtoupper($type) === 'WARNING' ? Severity::Warning : Severity::Error,
                    'phpcs',
                    ['type' => strtoupper($type), 'severity' => $severity, 'column' => $message['column'] ?? null]
                );
            }
        }

        return $issues;
    }
}
