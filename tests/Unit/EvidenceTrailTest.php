<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Rampart\QualityChecker\Semantic\EvidenceTrail;

/**
 * v0.5.1 negative-evidence contract: dynamic shapes are unresolved,
 * never missing; output JSON is stable.
 */
final class EvidenceTrailTest extends TestCase
{
    public function testTrailShape(): void
    {
        $trail = (new EvidenceTrail())
            ->found('form-request-param', 'App\\Http\\Requests\\StoreRequest')
            ->missing('form-request-rules', 'declares no rules()')
            ->unresolved('inline-validate', 'dynamic argument')
            ->conclude('missing-validation');

        self::assertSame(
            [
                'checks' => [
                    ['check' => 'form-request-param', 'status' => 'found', 'detail' => 'App\\Http\\Requests\\StoreRequest'],
                    ['check' => 'form-request-rules', 'status' => 'missing', 'detail' => 'declares no rules()'],
                    ['check' => 'inline-validate', 'status' => 'unresolved', 'detail' => 'dynamic argument'],
                ],
                'conclusion' => 'missing-validation',
            ],
            $trail->toArray()
        );
    }

    public function testEmptyTrail(): void
    {
        self::assertSame(
            ['checks' => [], 'conclusion' => ''],
            (new EvidenceTrail())->toArray()
        );
    }
}
