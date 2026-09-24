<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use VietVang\QualityChecker\Checkers\CustomAnalyzerChecker;
use VietVang\QualityChecker\Result\Issue;
use VietVang\QualityChecker\Result\Severity;
use VietVang\QualityChecker\Runner\CheckContext;
use VietVang\QualityChecker\Suppression\InlineSuppressor;

final class InlineSuppressorTest extends TestCase
{
    private function tempFile(string $content): string
    {
        $path = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-suppress-' . uniqid('', true) . '.php';
        file_put_contents($path, $content);

        return $path;
    }

    private function issue(string $file, int $line, string $rule = 'OWASP_SSRF'): Issue
    {
        return new Issue($rule, 'msg', $file, $line, Severity::Error, 'custom');
    }

    public function testSameLineIgnoreSuppressesMatchingRule(): void
    {
        $file = $this->tempFile("<?php\n\$data = file_get_contents(\$url); // quality-checker-ignore OWASP_SSRF\n");

        $kept = (new InlineSuppressor())->filter([$this->issue($file, 2)]);

        self::assertCount(0, $kept);
    }

    public function testSameLineIgnoreKeepsOtherRule(): void
    {
        $file = $this->tempFile("<?php\n\$data = file_get_contents(\$url); // quality-checker-ignore OWASP_XXE\n");

        $kept = (new InlineSuppressor())->filter([$this->issue($file, 2)]);

        self::assertCount(1, $kept);
    }

    public function testNextLineIgnoreSuppressesFollowingLine(): void
    {
        $file = $this->tempFile("<?php\n// quality-checker-ignore-next-line OWASP_SSRF\n\$data = file_get_contents(\$url);\n");

        $kept = (new InlineSuppressor())->filter([$this->issue($file, 3)]);

        self::assertCount(0, $kept);
    }

    public function testSameLineMarkerOnPreviousLineDoesNotSuppress(): void
    {
        $file = $this->tempFile("<?php\n// quality-checker-ignore OWASP_SSRF\n\$data = file_get_contents(\$url);\n");

        $kept = (new InlineSuppressor())->filter([$this->issue($file, 3)]);

        self::assertCount(1, $kept);
    }

    public function testAllSuppressesEveryRule(): void
    {
        $file = $this->tempFile("<?php\n\$x = 1; // quality-checker-ignore all\n");

        $suppressor = new InlineSuppressor();
        $kept = $suppressor->filter([
            $this->issue($file, 2, 'OWASP_SSRF'),
            $this->issue($file, 2, 'OWASP_XXE'),
        ]);

        self::assertCount(0, $kept);
        self::assertSame(2, $suppressor->countSuppressed());
    }

    public function testCommaSeparatedRuleList(): void
    {
        $file = $this->tempFile("<?php\n\$x = 1; # quality-checker-ignore OWASP_SSRF, OWASP_XXE\n");

        $kept = (new InlineSuppressor())->filter([$this->issue($file, 2, 'OWASP_XXE')]);

        self::assertCount(0, $kept);
    }

    public function testNoCommentKeepsIssue(): void
    {
        $file = $this->tempFile("<?php\n\$data = file_get_contents(\$url);\n");

        $suppressor = new InlineSuppressor();
        $kept = $suppressor->filter([$this->issue($file, 2)]);

        self::assertCount(1, $kept);
        self::assertSame(0, $suppressor->countSuppressed());
    }

    public function testMissingFileOrLineKeepsIssue(): void
    {
        $suppressor = new InlineSuppressor();
        $kept = $suppressor->filter([
            new Issue('OWASP_SSRF', 'msg', '/no/such/file.php', 1, Severity::Error, 'custom'),
            new Issue('OWASP_SSRF', 'msg', null, null, Severity::Error, 'custom'),
        ]);

        self::assertCount(2, $kept);
    }

    public function testCustomCheckerHonorsInlineIgnore(): void
    {
        $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-suppress-e2e-' . uniqid('', true);
        @mkdir($dir . DIRECTORY_SEPARATOR . 'app' . DIRECTORY_SEPARATOR . 'Services', 0777, true);
        file_put_contents(
            $dir . DIRECTORY_SEPARATOR . 'app' . DIRECTORY_SEPARATOR . 'Services' . DIRECTORY_SEPARATOR . 'S.php',
            "<?php\nclass S {\n    public function fetch(string \$url): string {\n        return (string) file_get_contents(\$url); // quality-checker-ignore OWASP_SSRF\n    }\n}\n"
        );

        $ctx = new CheckContext(
            $dir,
            ['app'],
            ['analyzers' => ['enabled' => true, 'owasp' => ['ssrf' => true]]],
            $dir . DIRECTORY_SEPARATOR . 'reports'
        );

        $result = (new CustomAnalyzerChecker())->run($ctx);

        self::assertCount(0, $result->issues);
        self::assertStringContainsString('suppressed', (string) $result->summary);
    }

    public function testCustomCheckerCanDisableInlineSuppression(): void
    {
        $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-suppress-off-' . uniqid('', true);
        @mkdir($dir . DIRECTORY_SEPARATOR . 'app', 0777, true);
        file_put_contents(
            $dir . DIRECTORY_SEPARATOR . 'app' . DIRECTORY_SEPARATOR . 'S.php',
            "<?php\n\$data = file_get_contents(\$url); // quality-checker-ignore OWASP_SSRF\n"
        );

        $ctx = new CheckContext(
            $dir,
            ['app'],
            ['analyzers' => ['enabled' => true, 'inline_suppression' => false, 'owasp' => ['ssrf' => true]]],
            $dir . DIRECTORY_SEPARATOR . 'reports'
        );

        $result = (new CustomAnalyzerChecker())->run($ctx);

        self::assertNotCount(0, $result->issues);
    }
}
