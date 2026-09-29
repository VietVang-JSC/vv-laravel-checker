<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Rampart\QualityChecker\Semantic\MassAssignmentDecision;
use Rampart\QualityChecker\Semantic\MassFlow;
use Rampart\QualityChecker\Semantic\ModelMetadata;
use Rampart\QualityChecker\Semantic\ModelMetadataIndex;

/**
 * v0.4.2 Source × Model assignability decisions + model metadata states.
 */
final class MassAssignmentDecisionTest extends TestCase
{
    /** @var list<string> */
    private array $dirs = [];

    protected function tearDown(): void
    {
        foreach ($this->dirs as $dir) {
            $this->removeDir($dir);
        }
        $this->dirs = [];
    }

    private function removeDir(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }
        foreach ((scandir($dir) ?: []) as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }
            $path = $dir . DIRECTORY_SEPARATOR . $item;
            if (is_dir($path)) {
                $this->removeDir($path);
            } else {
                @unlink($path);
            }
        }
        @rmdir($dir);
    }

    /**
     * @param array<string, string> $files relPath => content
     * @return list<string> absolute paths
     */
    private function project(array $files): array
    {
        $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-mass-' . uniqid('', true);
        @mkdir($dir, 0777, true);
        $this->dirs[] = $dir;
        $paths = [];
        foreach ($files as $rel => $content) {
            $path = $dir . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $rel);
            @mkdir(dirname($path), 0777, true);
            file_put_contents($path, $content);
            $paths[] = $path;
        }

        return $paths;
    }

    /**
     * @param list<string>|null $fields
     */
    private function flow(string $status, bool $force = false, ?array $fields = null): MassFlow
    {
        return new MassFlow($status, $fields, null, $force, '$request->all()', 'create()', []);
    }

    private function meta(string $modelBody, string $model = 'App\\Models\\User'): ModelMetadata
    {
        $paths = $this->project([
            'app/Models/User.php' => "<?php\nnamespace App\\Models;\n" .
                "class User extends \\Illuminate\\Database\\Eloquent\\Model {\n{$modelBody}}\n",
        ]);

        return ModelMetadata::fromFile($model, $paths[0]);
    }

    public function testFillableStates(): void
    {
        $meta = $this->meta("    protected \$fillable = ['name', 'email'];\n");
        self::assertSame('known', $meta->fillableState);
        self::assertSame(['name', 'email'], $meta->fillableFields);
        self::assertSame(['fillable', ['name', 'email']], $meta->assignability());
    }

    public function testGuardedEmptyIsUnguarded(): void
    {
        $meta = $this->meta("    protected \$guarded = [];\n");
        self::assertSame(['unguarded', null], $meta->assignability());
    }

    public function testGuardedStarIsGuardedAll(): void
    {
        $meta = $this->meta("    protected \$guarded = ['*'];\n");
        self::assertSame(['guarded-all', []], $meta->assignability());
    }

    public function testAbsentBothIsDefaultGuarded(): void
    {
        // Framework default $guarded = ['*']: nothing assignable.
        $meta = $this->meta('');
        self::assertSame(['guarded-all', []], $meta->assignability());
    }

    public function testGuardedListIsGuardedList(): void
    {
        $meta = $this->meta("    protected \$guarded = ['is_admin', 'role'];\n");
        self::assertSame(['guarded-list', null], $meta->assignability());
    }

    public function testDynamicIsUnknown(): void
    {
        // Unknown must never degrade into empty.
        $meta = $this->meta("    protected \$fillable = \$fields;\n");
        self::assertSame('unknown', $meta->fillableState);
        self::assertNull($meta->fillableFields);
        self::assertSame(['unknown', null], $meta->assignability());
    }

    public function testRawIntoUnguardedIsExposed(): void
    {
        $decision = MassAssignmentDecision::decide(
            $this->flow(MassFlow::RAW),
            $this->meta("    protected \$guarded = [];\n")
        );

        self::assertSame('exposed', $decision->verdict);
        self::assertSame('unguarded', $decision->assignability);
    }

    public function testRawIntoFillableIsSafe(): void
    {
        $decision = MassAssignmentDecision::decide(
            $this->flow(MassFlow::RAW),
            $this->meta("    protected \$fillable = ['name', 'email'];\n")
        );

        self::assertSame('safe', $decision->verdict);
        self::assertSame(['name', 'email'], $decision->assignableFields);
    }

    public function testValidatedIntoUnguardedIsNotSafe(): void
    {
        // Validated is never auto-safe.
        $decision = MassAssignmentDecision::decide(
            $this->flow(MassFlow::VALIDATED),
            $this->meta("    protected \$guarded = [];\n")
        );

        self::assertSame('review', $decision->verdict);
    }

    public function testBoundedIntoUnguardedIsReview(): void
    {
        $decision = MassAssignmentDecision::decide(
            $this->flow(MassFlow::BOUNDED, false, ['name', 'email']),
            $this->meta("    protected \$guarded = [];\n")
        );

        self::assertSame('review', $decision->verdict);
        self::assertSame(['name', 'email'], $decision->inputFields);
    }

    public function testInternalIsSafeEverywhere(): void
    {
        $decision = MassAssignmentDecision::decide(
            $this->flow(MassFlow::INTERNAL),
            $this->meta("    protected \$guarded = [];\n")
        );

        self::assertSame('safe', $decision->verdict);
    }

    public function testUnknownModelIsUnknown(): void
    {
        $decision = MassAssignmentDecision::decide($this->flow(MassFlow::RAW), null);

        self::assertSame('unknown', $decision->verdict);
    }

    public function testForceRawIntoFillableIsExposed(): void
    {
        // force* bypasses model protection in reasoning.
        $decision = MassAssignmentDecision::decide(
            $this->flow(MassFlow::RAW, true),
            $this->meta("    protected \$fillable = ['name'];\n")
        );

        self::assertSame('exposed', $decision->verdict);
    }

    public function testForceBoundedIsReview(): void
    {
        $decision = MassAssignmentDecision::decide(
            $this->flow(MassFlow::BOUNDED, true, ['name']),
            $this->meta("    protected \$fillable = ['name'];\n")
        );

        self::assertSame('review', $decision->verdict);
    }

    public function testGlobalUnguardExposes(): void
    {
        $decision = MassAssignmentDecision::decide(
            $this->flow(MassFlow::RAW),
            $this->meta("    protected \$fillable = ['name'];\n"),
            true
        );

        self::assertSame('exposed', $decision->verdict);
    }

    public function testBoundedFullyGuardedIsSafe(): void
    {
        $decision = MassAssignmentDecision::decide(
            $this->flow(MassFlow::BOUNDED, false, ['is_admin']),
            $this->meta("    protected \$guarded = ['is_admin', 'role'];\n")
        );

        self::assertSame('safe', $decision->verdict);
    }

    public function testBoundedPartiallyGuardedIsReview(): void
    {
        $decision = MassAssignmentDecision::decide(
            $this->flow(MassFlow::BOUNDED, false, ['name', 'is_admin']),
            $this->meta("    protected \$guarded = ['is_admin'];\n")
        );

        self::assertSame('review', $decision->verdict);
    }

    public function testGlobalUnguardDetected(): void
    {
        $paths = $this->project([
            'app/Models/User.php' => "<?php\nnamespace App\\Models;\nclass User extends \\Illuminate\\Database\\Eloquent\\Model {}\n",
            'app/Providers/AppServiceProvider.php' => "<?php\nnamespace App\\Providers;\n" .
                "use Illuminate\\Database\\Eloquent\\Model;\n" .
                "class AppServiceProvider {\n    public function boot() {\n        Model::unguard();\n    }\n}\n",
        ]);
        $index = new ModelMetadataIndex($paths);

        self::assertTrue($index->globallyUnguarded());
        self::assertNotNull($index->metadataFor('App\\Models\\User'));
    }

    public function testReguardClearsGlobal(): void
    {
        $paths = $this->project([
            'app/Providers/AppServiceProvider.php' => "<?php\nnamespace App\\Providers;\n" .
                "use Illuminate\\Database\\Eloquent\\Model;\n" .
                "class AppServiceProvider {\n    public function boot() {\n        Model::unguard();\n        Model::reguard();\n    }\n" .
                "}\n",
        ]);

        self::assertFalse((new ModelMetadataIndex($paths))->globallyUnguarded());
    }

    public function testSeederUnguardIgnored(): void
    {
        $paths = $this->project([
            'database/seeders/UserSeeder.php' => "<?php\nnamespace Database\\Seeders;\n" .
                "use Illuminate\\Database\\Eloquent\\Model;\n" .
                "class UserSeeder {\n    public function run() {\n        Model::unguard();\n    }\n" .
                "}\n",
        ]);

        self::assertFalse((new ModelMetadataIndex($paths))->globallyUnguarded());
    }
}
