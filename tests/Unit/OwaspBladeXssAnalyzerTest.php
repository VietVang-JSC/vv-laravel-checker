<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use VietVang\QualityChecker\Analyzers\Owasp\OwaspBladeXssAnalyzer;
use VietVang\QualityChecker\Result\Issue;
use VietVang\QualityChecker\Result\Severity;

final class OwaspBladeXssAnalyzerTest extends TestCase
{
    private function temp(string $content, string $relPath): string
    {
        $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-bladexss-' . uniqid('', true);
        $path = $dir . DIRECTORY_SEPARATOR . $relPath;
        @mkdir(dirname($path), 0777, true);
        file_put_contents($path, $content);

        return $path;
    }

    /**
     * @param list<Issue> $issues
     * @return list<string>
     */
    private function rules(array $issues): array
    {
        return array_map(static fn ($i) => $i->rule, $issues);
    }

    public function testFlagsUnescapedVariable(): void
    {
        $file = $this->temp(
            "<div>{!! \$comment->body !!}</div>\n",
            'resources/views/comments/show.blade.php'
        );

        $issues = (new OwaspBladeXssAnalyzer())->analyze([$file]);

        self::assertCount(1, $issues);
        self::assertSame('OWASP_BLADE_XSS', $issues[0]->rule);
        self::assertSame(Severity::Error, $issues[0]->severity);
    }

    public function testFlagsRequestHelper(): void
    {
        $file = $this->temp(
            "<div>{!! request('x') !!}</div>\n",
            'resources/views/search/show.blade.php'
        );

        $issues = (new OwaspBladeXssAnalyzer())->analyze([$file]);

        self::assertCount(1, $issues);
        self::assertSame('OWASP_BLADE_XSS', $issues[0]->rule);
    }

    public function testSkipsCsrfField(): void
    {
        $file = $this->temp(
            "<form>{!! csrf_field() !!}</form>\n",
            'resources/views/forms/create.blade.php'
        );

        $issues = (new OwaspBladeXssAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testSkipsEscapedEcho(): void
    {
        $file = $this->temp(
            "<div>{{ \$name }}</div>\n",
            'resources/views/users/show.blade.php'
        );

        $issues = (new OwaspBladeXssAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testSkipsManuallyEscaped(): void
    {
        $file = $this->temp(
            "<div>{!! e(\$x) !!}</div>\n",
            'resources/views/users/show.blade.php'
        );

        $issues = (new OwaspBladeXssAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testSkipsRenderedHtmlConvention(): void
    {
        $file = $this->temp(
            "<div>{!! \$commentHtml !!}</div>\n<div>{!! \$book->descriptionInfo()->getHtml() !!}</div>\n",
            'resources/views/comments/comment.blade.php'
        );

        $issues = (new OwaspBladeXssAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testStillFlagsPlainVariable(): void
    {
        $file = $this->temp(
            "<div>{!! \$comment->body !!}</div>\n",
            'resources/views/comments/show.blade.php'
        );

        $issues = (new OwaspBladeXssAnalyzer())->analyze([$file]);

        self::assertSame('OWASP_BLADE_XSS', $this->rules($issues)[0] ?? null);
    }

    public function testSkipsNonBladeExtension(): void
    {
        $file = $this->temp(
            "<div>{!! \$comment->body !!}</div>\n",
            'resources/views/comments/show.php'
        );

        $issues = (new OwaspBladeXssAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testReportsCorrectLineNumber(): void
    {
        $file = $this->temp(
            "<div>ok</div>\n<div>{{ \$name }}</div>\n<div>{!! \$comment->body !!}</div>\n",
            'resources/views/comments/index.blade.php'
        );

        $issues = (new OwaspBladeXssAnalyzer())->analyze([$file]);

        self::assertCount(1, $issues);
        self::assertSame(3, $issues[0]->line);
    }
}
