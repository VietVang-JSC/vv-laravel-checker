<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Rampart\QualityChecker\Baseline\BaselineManager;
use Rampart\QualityChecker\Baseline\IssueDelta;

final class IssueDeltaTest extends TestCase
{
    /** @return array<string, mixed> */
    private function issue(string $rule, string $file, int $line, string $message): array
    {
        return ['rule' => $rule, 'file' => $file, 'line' => $line, 'message' => $message];
    }

    public function testSplitsNewFixedExisting(): void
    {
        $manager = new BaselineManager();
        $old = $this->issue('RULE_A', 'a.php', 1, 'm1');
        $kept = $this->issue('RULE_B', 'b.php', 2, 'm2');
        $new = $this->issue('RULE_C', 'c.php', 3, 'm3');

        $baseline = [];
        foreach ([$old, $kept] as $issue) {
            $sig = $manager->signature($issue);
            self::assertNotNull($sig);
            $baseline[$sig] = $sig;
        }

        $delta = IssueDelta::compute([$kept, $new], $baseline);

        self::assertCount(1, $delta['new']);
        self::assertSame('RULE_C', $delta['new'][0]['rule']);
        self::assertSame(1, $delta['fixed']);
        self::assertSame(1, $delta['existing']);
        self::assertSame(['RULE_C' => 1], $delta['new_by_rule']);
    }

    public function testEmptyBaselineMeansAllNew(): void
    {
        $delta = IssueDelta::compute([$this->issue('RULE_A', 'a.php', 1, 'm1')], []);

        self::assertCount(1, $delta['new']);
        self::assertSame(0, $delta['fixed']);
        self::assertSame(0, $delta['existing']);
    }

    public function testEmptyCurrentMeansAllFixed(): void
    {
        $manager = new BaselineManager();
        $sig = $manager->signature($this->issue('RULE_A', 'a.php', 1, 'm1'));

        $delta = IssueDelta::compute([], [$sig => $sig]);

        self::assertSame([], $delta['new']);
        self::assertSame(1, $delta['fixed']);
        self::assertSame(0, $delta['existing']);
    }

    public function testMovedLineCountsAsNewPlusFixed(): void
    {
        $manager = new BaselineManager();
        $before = $this->issue('RULE_A', 'a.php', 1, 'm1');
        $sig = $manager->signature($before);
        self::assertNotNull($sig);

        $after = $this->issue('RULE_A', 'a.php', 5, 'm1');
        $delta = IssueDelta::compute([$after], [$sig => $sig]);

        self::assertCount(1, $delta['new']);
        self::assertSame(1, $delta['fixed']);
    }
}
