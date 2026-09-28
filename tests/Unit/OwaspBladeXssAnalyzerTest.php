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
            "<div>{!! \$commentHtml !!}</div>\n<div>{!! \$book->descriptionInfo()->getHtml() !!}</div>\n<div>{!! \$page->renderedHTML !!}</div>\n",
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

    public function testSkipsSanitizerWrapped(): void
    {
        $file = $this->temp(
            "<div>{!! sanitizeHtml(\$exercise_detail->student_content) !!}</div>\n<div>{!! strip_tags(\$x) !!}</div>\n",
            'resources/views/frontend/lesson/detail.blade.php'
        );

        $issues = (new OwaspBladeXssAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testSkipsPaginatorLinks(): void
    {
        $file = $this->temp(
            "<div>{!! \$importCreatedRows->links('pagination::bootstrap-4') !!}</div>\n",
            'resources/views/customer/partials/tables.blade.php'
        );

        $issues = (new OwaspBladeXssAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testSkipsFrameworkEventOutput(): void
    {
        $file = $this->temp(
            "<div>{!! view_render_event('bagisto.shop.layout.header.before') !!}</div>\n",
            'packages/Webkul/Shop/src/Resources/views/layouts/header.blade.php'
        );

        $issues = (new OwaspBladeXssAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testSkipsFormBuilderOutput(): void
    {
        $file = $this->temp(
            "<div>{!! Form::model(\$event, ['route' => route('events.show', ['id' => \$event->id])]) !!}</div>\n",
            'resources/views/events/edit.blade.php'
        );

        $issues = (new OwaspBladeXssAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testSkipsHtmlBuilderOutput(): void
    {
        $file = $this->temp(
            "<div>{!! Html::sortable_link(trans('Name'), \$sort, 'name') !!}</div>\n",
            'resources/views/events/index.blade.php'
        );

        $issues = (new OwaspBladeXssAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testSkipsPaginatorAppendsRender(): void
    {
        $file = $this->temp(
            "<div>{!! \$events->appends(['sort' => 'name'])->render() !!}</div>\n",
            'resources/views/events/index.blade.php'
        );

        $issues = (new OwaspBladeXssAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testSkipsJsonEncodeWithHexFlags(): void
    {
        $file = $this->temp(
            "<script>var C = {!! json_encode(\$cfg, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT) !!};</script>\n",
            'resources/views/pos/index.blade.php'
        );

        $issues = (new OwaspBladeXssAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testFlagsJsonEncodeWithoutHexFlags(): void
    {
        $file = $this->temp(
            "<script>var C = {!! json_encode(\$cfg) !!};</script>\n",
            'resources/views/pos/index.blade.php'
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

    public function testFlagsDynamicInclude(): void
    {
        $file = $this->temp(
            "@include(\$view)\n",
            'resources/views/pages/show.blade.php'
        );

        $issues = (new OwaspBladeXssAnalyzer())->analyze([$file]);

        self::assertCount(1, $issues);
        self::assertSame('OWASP_BLADE_XSS', $issues[0]->rule);
        self::assertSame('dynamic-include', $issues[0]->metadata['kind'] ?? null);
    }

    public function testFlagsDynamicExtendsConcat(): void
    {
        $file = $this->temp(
            "@extends('layouts.' . \$theme)\n",
            'resources/views/pages/show.blade.php'
        );

        $issues = (new OwaspBladeXssAnalyzer())->analyze([$file]);

        self::assertCount(1, $issues);
        self::assertSame('OWASP_BLADE_XSS', $issues[0]->rule);
    }

    public function testFlagsDynamicIncludeWhenView(): void
    {
        $file = $this->temp(
            "@includeWhen(\$showBanner, \$bannerView)\n",
            'resources/views/pages/show.blade.php'
        );

        $issues = (new OwaspBladeXssAnalyzer())->analyze([$file]);

        self::assertCount(1, $issues);
    }

    public function testSkipsLiteralInclude(): void
    {
        $file = $this->temp(
            "@include('partials.header')\n",
            'resources/views/pages/show.blade.php'
        );

        $issues = (new OwaspBladeXssAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testSkipsLiteralExtends(): void
    {
        $file = $this->temp(
            "@extends('layouts.app')\n",
            'resources/views/pages/show.blade.php'
        );

        $issues = (new OwaspBladeXssAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testSkipsIncludeWhenWithLiteralView(): void
    {
        $file = $this->temp(
            "@includeWhen(\$showBanner, 'partials.banner')\n",
            'resources/views/pages/show.blade.php'
        );

        $issues = (new OwaspBladeXssAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testSkipsLiteralIncludeFirstList(): void
    {
        $file = $this->temp(
            "@includeFirst(['custom.header', 'partials.header'])\n",
            'resources/views/pages/show.blade.php'
        );

        $issues = (new OwaspBladeXssAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testSkipsNumberCurrencyHelper(): void
    {
        $file = $this->temp(
            "<div>{!! Number::currency(\$order->total, 'USD') !!}</div>\n",
            'resources/views/orders/show.blade.php'
        );

        $issues = (new OwaspBladeXssAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testSkipsVerifiedAmountFormatter(): void
    {
        $file = $this->temp(
            "<div>{!! format_amount_by_symbol(\$row['sum'], \$row['currency_symbol'], 2) !!}</div>\n",
            'resources/views/reports/budget.blade.php'
        );

        $issues = (new OwaspBladeXssAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testSkipsAmountFormatterFamily(): void
    {
        $file = $this->temp(
            "<div>{!! format_amount_by_currency(\$currency, \$account['max_amount']) !!}</div>\n<div>{!! format_amount_by_account(\$account, \$clearedAmount) !!}</div>\n",
            'resources/views/reports/budget.blade.php'
        );

        $issues = (new OwaspBladeXssAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testStillFlagsUnknownFormatter(): void
    {
        $file = $this->temp(
            "<div>{!! format_html(\$user->bio) !!}</div>\n",
            'resources/views/users/show.blade.php'
        );

        $issues = (new OwaspBladeXssAnalyzer())->analyze([$file]);

        self::assertSame('OWASP_BLADE_XSS', $this->rules($issues)[0] ?? null);
    }

    public function testSkipsLiteralTernaryBranches(): void
    {
        $file = $this->temp(
            "<div>{!! \$checked ? 'checked=\"checked\"' : '' !!}</div>\n",
            'resources/views/formfields/checkbox.blade.php'
        );

        $issues = (new OwaspBladeXssAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testStillFlagsElvisOperator(): void
    {
        $file = $this->temp(
            "<div>{!! \$name ?: 'anonymous' !!}</div>\n",
            'resources/views/users/show.blade.php'
        );

        $issues = (new OwaspBladeXssAnalyzer())->analyze([$file]);

        self::assertSame('OWASP_BLADE_XSS', $this->rules($issues)[0] ?? null);
    }

    public function testStillFlagsDynamicTernaryBranch(): void
    {
        $file = $this->temp(
            "<div>{!! \$ok ? \$name : 'anonymous' !!}</div>\n",
            'resources/views/users/show.blade.php'
        );

        $issues = (new OwaspBladeXssAnalyzer())->analyze([$file]);

        self::assertSame('OWASP_BLADE_XSS', $this->rules($issues)[0] ?? null);
    }

    public function testSkipsExcerptMethod(): void
    {
        $file = $this->temp(
            "<div>{!! \$article->excerpt() !!}</div>\n",
            'resources/views/articles/summary.blade.php'
        );

        $issues = (new OwaspBladeXssAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testSkipsMdToHtml(): void
    {
        $file = $this->temp(
            "<div>{!! md_to_html(\$article->body()) !!}</div>\n",
            'resources/views/articles/show.blade.php'
        );

        $issues = (new OwaspBladeXssAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testSkipsSafeRawHtml(): void
    {
        $file = $this->temp(
            "<div>{!! safe_raw_html(\$flash['text']) !!}</div>\n<div>{!! __safe_raw_html('key', ['count' => \$n]) !!}</div>\n",
            'resources/views/partials/flash.blade.php'
        );

        $issues = (new OwaspBladeXssAnalyzer())->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testSkipsExtraSanitizerNeedle(): void
    {
        $file = $this->temp(
            "<div>{!! mySanitize(\$comment->body) !!}</div>\n",
            'resources/views/comments/show.blade.php'
        );

        $issues = (new OwaspBladeXssAnalyzer(['extra_sanitizers' => ['mySanitize']]))->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testSkipsExtraSanitizerPrefixNeedle(): void
    {
        $file = $this->temp(
            "<div>{!! ShopHtml::render(\$comment->body) !!}</div>\n",
            'resources/views/comments/show.blade.php'
        );

        $issues = (new OwaspBladeXssAnalyzer(['extra_sanitizers' => ['shophtml::']]))->analyze([$file]);

        self::assertCount(0, $issues);
    }

    public function testStillFlagsExtraSanitizerContentWithDefaultOptions(): void
    {
        $file = $this->temp(
            "<div>{!! mySanitize(\$comment->body) !!}</div>\n",
            'resources/views/comments/show.blade.php'
        );

        $issues = (new OwaspBladeXssAnalyzer())->analyze([$file]);

        self::assertSame('OWASP_BLADE_XSS', $this->rules($issues)[0] ?? null);
    }

    public function testStillFlagsPlainVariableWithExtraSanitizerConfigured(): void
    {
        $file = $this->temp(
            "<div>{!! \$comment->body !!}</div>\n",
            'resources/views/comments/show.blade.php'
        );

        $issues = (new OwaspBladeXssAnalyzer(['extra_sanitizers' => ['mySanitize']]))->analyze([$file]);

        self::assertSame('OWASP_BLADE_XSS', $this->rules($issues)[0] ?? null);
    }
}
