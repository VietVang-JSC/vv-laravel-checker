<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Tests\Unit;

use Closure;
use PHPUnit\Framework\TestCase;
use VietVang\QualityChecker\Analyzers\AbstractAnalyzer;
use VietVang\QualityChecker\Analyzers\Laravel\MigrationAnalyzer;
use VietVang\QualityChecker\Analyzers\Owasp\OwaspAccessControlAnalyzer;
use VietVang\QualityChecker\Analyzers\Owasp\OwaspCommandInjectionAnalyzer;
use VietVang\QualityChecker\Analyzers\Owasp\OwaspSsrfAnalyzer;
use VietVang\QualityChecker\Analyzers\Owasp\OwaspXxeAnalyzer;
use VietVang\QualityChecker\Analyzers\Security\InsecureHashAnalyzer;
use VietVang\QualityChecker\Result\Issue;

/**
 * Labeled precision/recall corpus for the FP-reduction work.
 *
 * Every case is either a true positive (must flag `expectedRule`) or a known
 * false positive (must stay silent). The aggregate test pins corpus-wide
 * precision and recall at 1.0, so any future change that reintroduces noise
 * or drops a true positive fails loudly.
 *
 * @see docs/false-positives.md
 */
final class AnalyzerMetricsTest extends TestCase
{
    /**
     * @return iterable<string, array{Closure(): (AbstractAnalyzer|InsecureHashAnalyzer), array<string, string>, string|null}>
     */
    public static function corpus(): iterable
    {
        // --- Broken access control ---
        yield 'bac_tp_unprotected_store' => [
            static fn (): AbstractAnalyzer => new OwaspAccessControlAnalyzer(),
            ['app/Http/Controllers/UserController.php' => "<?php\nnamespace App\\Http\\Controllers;\nclass UserController extends Controller {\n    public function store() {\n        \$this->user()->save();\n    }\n}\n"],
            'OWASP_BROKEN_ACCESS_CONTROL',
        ];
        yield 'bac_fp_chain_middleware' => [
            static fn (): AbstractAnalyzer => new OwaspAccessControlAnalyzer(),
            [
                'app/Http/Controllers/BackupController.php' => "<?php\nnamespace App\\Http\\Controllers;\nclass BackupController extends Controller {\n    public function store() {\n        \$this->model->save();\n    }\n}\n",
                'routes/web.php' => "<?php\nuse Illuminate\\Support\\Facades\\Route;\nRoute::post('/backup', 'App\\Http\\Controllers\\BackupController@store')->middleware('can:admin-only');\n",
            ],
            null,
        ];
        yield 'bac_fp_group_middleware' => [
            static fn (): AbstractAnalyzer => new OwaspAccessControlAnalyzer(),
            [
                'app/Http/Controllers/BackupController.php' => "<?php\nnamespace App\\Http\\Controllers;\nclass BackupController extends Controller {\n    public function destroy() {\n        \$this->model->delete();\n    }\n}\n",
                'routes/web.php' => "<?php\nuse Illuminate\\Support\\Facades\\Route;\nRoute::group(['middleware' => ['checkLevel']], function () {\n    Route::post('/backup/delete', 'App\\Http\\Controllers\\BackupController@destroy');\n});\n",
            ],
            null,
        ];
        yield 'bac_fp_controller_group' => [
            static fn (): AbstractAnalyzer => new OwaspAccessControlAnalyzer(),
            [
                'app/Http/Controllers/AttributeController.php' => "<?php\nnamespace App\\Http\\Controllers;\nclass AttributeController extends Controller {\n    public function store() {\n        \$this->model->save();\n    }\n}\n",
                'routes/web.php' => "<?php\nuse Illuminate\\Support\\Facades\\Route;\nuse App\\Http\\Controllers\\AttributeController;\nRoute::middleware(['admin'])->group(function () {\n    Route::controller(AttributeController::class)->group(function () {\n        Route::post('create', 'store');\n    });\n});\n",
            ],
            null,
        ];
        yield 'bac_fp_legacy_uses' => [
            static fn (): AbstractAnalyzer => new OwaspAccessControlAnalyzer(),
            [
                'src/Controller/AccountController.php' => "<?php\nnamespace Aimeos\\Shop\\Controller;\nclass AccountController extends Controller {\n    public function store() {\n        \$this->model->save();\n    }\n}\n",
                'routes/shop.php' => "<?php\nuse Illuminate\\Support\\Facades\\Route;\nRoute::group(['middleware' => ['web', 'auth']], function () {\n    Route::match(['POST'], 'profile', ['as' => 'shop.account', 'uses' => 'Aimeos\\\\Shop\\\\Controller\\\\AccountController@store']);\n});\n",
            ],
            null,
        ];
        yield 'bac_tp_throttle_only' => [
            static fn (): AbstractAnalyzer => new OwaspAccessControlAnalyzer(),
            [
                'app/Http/Controllers/PushController.php' => "<?php\nnamespace App\\Http\\Controllers;\nclass PushController extends Controller {\n    public function store() {\n        \$this->model->save();\n    }\n}\n",
                'routes/web.php' => "<?php\nuse Illuminate\\Support\\Facades\\Route;\nRoute::post('/push', 'App\\Http\\Controllers\\PushController@store')->middleware('throttle:forms');\n",
            ],
            'OWASP_BROKEN_ACCESS_CONTROL',
        ];

        // --- Command injection ---
        yield 'cmd_tp_system_request' => [
            static fn (): AbstractAnalyzer => new OwaspCommandInjectionAnalyzer(),
            ['app/Console/Commands/RunCommand.php' => "<?php\nsystem(\$request->input('cmd'));\n"],
            'OWASP_COMMAND_INJECTION',
        ];
        yield 'cmd_fp_escapeshellarg' => [
            static fn (): AbstractAnalyzer => new OwaspCommandInjectionAnalyzer(),
            ['app/Services/BackupService.php' => "<?php\n\$fromPath = trim((string) shell_exec('where ' . escapeshellarg(\$tool)));\n"],
            null,
        ];
        yield 'cmd_fp_process_array' => [
            static fn (): AbstractAnalyzer => new OwaspCommandInjectionAnalyzer(),
            ['app/Services/BackupService.php' => "<?php\nclass BackupService {\n    public function create(): void {\n        \$command = ['mysqldump', '-h', 'localhost'];\n        \$process = new Symfony\\Component\\Process\\Process(\$command);\n        \$process->run();\n    }\n}\n"],
            null,
        ];
        yield 'cmd_fp_deploy_concat' => [
            static fn (): AbstractAnalyzer => new OwaspCommandInjectionAnalyzer(),
            ['app/Console/Commands/SetupDocs.php' => "<?php\nclass SetupDocs {\n    protected function documentation(): void {\n        \$artisan = base_path('artisan');\n        passthru(PHP_BINARY . \" \$artisan migrate:fresh --force -q\");\n    }\n}\n"],
            null,
        ];
        yield 'cmd_tp_derived_var' => [
            static fn (): AbstractAnalyzer => new OwaspCommandInjectionAnalyzer(),
            ['app/Console/Commands/SetupDocs.php' => "<?php\nclass SetupDocs {\n    protected function documentation(): void {\n        \$v = \$this->getVerbosity();\n        passthru(PHP_BINARY . \" artisan scribe:generate --force\$v\");\n    }\n}\n"],
            'OWASP_COMMAND_INJECTION',
        ];
        yield 'cmd_tp_exec_param' => [
            static fn (): AbstractAnalyzer => new OwaspCommandInjectionAnalyzer(),
            ['app/Helpers/helpers.php' => "<?php\nfunction readVersion(string \$gitCommand): string {\n    \$command = \\Illuminate\\Support\\Str::of(\$gitCommand)->start('git ');\n    return trim(exec(\"\$command 2>/dev/null\"));\n}\n"],
            'OWASP_COMMAND_INJECTION',
        ];

        // --- SSRF ---
        yield 'ssrf_tp_request_input' => [
            static fn (): AbstractAnalyzer => new OwaspSsrfAnalyzer(),
            ['app/Services/ExternalService.php' => "<?php\n\$data = file_get_contents(\$request->input('url'));\n"],
            'OWASP_SSRF',
        ];
        yield 'ssrf_fp_fopen_write' => [
            static fn (): AbstractAnalyzer => new OwaspSsrfAnalyzer(),
            ['app/Jobs/ExportBankFileJob.php' => "<?php\n\$handle = fopen(\$fullPath, 'w');\n"],
            null,
        ];
        yield 'ssrf_fp_local_var' => [
            static fn (): AbstractAnalyzer => new OwaspSsrfAnalyzer(),
            ['app/Services/BackupService.php' => "<?php\n\$contents = file_get_contents(\$source);\n"],
            null,
        ];
        yield 'ssrf_fp_getrealpath' => [
            static fn (): AbstractAnalyzer => new OwaspSsrfAnalyzer(),
            ['app/Uploads/ImageService.php' => "<?php\nclass ImageService {\n    public function store(\$file): string {\n        return (string) file_get_contents(\$file->getRealPath());\n    }\n}\n"],
            null,
        ];
        yield 'ssrf_fp_guzzle_constructor' => [
            static fn (): AbstractAnalyzer => new OwaspSsrfAnalyzer(),
            ['app/Http/HttpRequestService.php' => "<?php\nclass HttpRequestService {\n    public function buildClient(int \$timeout): object {\n        return new GuzzleHttp\\Client(['timeout' => \$timeout]);\n    }\n}\n"],
            null,
        ];
        yield 'ssrf_fp_env_lookup' => [
            static fn (): AbstractAnalyzer => new OwaspSsrfAnalyzer(),
            ['config/cache.php' => "<?php\nif (env('APP_SECRETS')) {\n    \$secrets = json_decode(file_get_contents(env('APP_SECRETS')), true);\n}\n"],
            null,
        ];
        yield 'ssrf_tp_url_var' => [
            static fn (): AbstractAnalyzer => new OwaspSsrfAnalyzer(),
            ['app/Services/ExternalService.php' => "<?php\n\$data = file_get_contents(\$url);\n"],
            'OWASP_SSRF',
        ];

        // --- XXE ---
        yield 'xxe_tp_sink' => [
            static fn (): AbstractAnalyzer => new OwaspXxeAnalyzer(),
            ['app/Services/XmlParser.php' => "<?php\n\$xml = simplexml_load_string(\$raw);\n"],
            'OWASP_XXE',
        ];
        yield 'xxe_fp_test_path' => [
            static fn (): AbstractAnalyzer => new OwaspXxeAnalyzer(),
            ['tests/Unit/GovEfileTest.php' => "<?php\n\$xml = simplexml_load_string(\$raw);\n"],
            null,
        ];

        // --- Insecure hash ---
        yield 'hash_tp_md5_password' => [
            static fn (): InsecureHashAnalyzer => new InsecureHashAnalyzer(),
            ['app/Services/AuthService.php' => "<?php\nnamespace App\\Services;\nclass AuthService {\n    public function verify(string \$password): bool {\n        return md5(\$password) === \$this->storedHash;\n    }\n}\n"],
            'INSECURE_HASH',
        ];
        yield 'hash_fp_hibp' => [
            static fn (): InsecureHashAnalyzer => new InsecureHashAnalyzer(),
            ['app/Services/PasswordBreachService.php' => "<?php\nnamespace App\\Services;\nclass PasswordBreachService {\n    public function breached(string \$password): bool {\n        \$prefix = strtoupper(substr(sha1(\$password), 0, 5));\n        \$body = file_get_contents('https://api.pwnedpasswords.com/range/' . \$prefix);\n        return str_contains((string) \$body, 'suffix');\n    }\n}\n"],
            null,
        ];

        // --- Migration ---
        yield 'mig_tp_dropcolumn_no_restore' => [
            static fn (): AbstractAnalyzer => new MigrationAnalyzer(),
            ['database/migrations/2026_01_01_x.php' => "<?php\nreturn new class extends Migration {\n    public function up(): void { Schema::table('holidays', function (Blueprint \$t) { \$t->dropColumn('country_id'); }); }\n    public function down(): void { Schema::dropIfExists('holidays_tmp'); }\n};\n"],
            'MIGRATION_DESTRUCTIVE_UP',
        ];
        yield 'mig_fp_dropcolumn_restored' => [
            static fn (): AbstractAnalyzer => new MigrationAnalyzer(),
            ['database/migrations/2026_01_01_y.php' => "<?php\nreturn new class extends Migration {\n    public function up(): void { Schema::table('holidays', function (Blueprint \$t) { \$t->dropColumn('country_id'); }); }\n    public function down(): void { Schema::table('holidays', function (Blueprint \$t) { \$t->string('country_id')->nullable(); }); }\n};\n"],
            null,
        ];
        yield 'mig_fp_dropindex' => [
            static fn (): AbstractAnalyzer => new MigrationAnalyzer(),
            ['database/migrations/2026_01_01_z.php' => "<?php\nreturn new class extends Migration {\n    public function up(): void { Schema::table('pages', function (Blueprint \$t) { \$t->dropIndex('search'); }); }\n    public function down(): void { }\n};\n"],
            null,
        ];
    }

    /**
     * @param Closure(): (AbstractAnalyzer|InsecureHashAnalyzer) $factory
     * @param array<string, string> $files
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('corpus')]
    public function testCorpusCase(Closure $factory, array $files, ?string $expectedRule): void
    {
        $paths = $this->materialize($files);
        $issues = $factory()->analyze($paths);

        /** @var list<string> $rules */
        $rules = [];
        foreach ($issues as $issue) {
            if ($issue instanceof Issue) {
                $rules[] = $issue->rule;
            }
        }

        if ($expectedRule === null) {
            self::assertCount(0, $issues, 'False positive regressed — expected silence.');
        } else {
            self::assertContains($expectedRule, $rules, 'True positive lost — expected ' . $expectedRule . '.');
        }
    }

    public function testCorpusPrecisionAndRecallArePerfect(): void
    {
        $truePositives = 0;
        $falsePositives = 0;
        $falseNegatives = 0;
        /** @var list<string> $failures */
        $failures = [];

        foreach (self::corpus() as $id => [$factory, $files, $expectedRule]) {
            $paths = $this->materialize($files);
            $issues = $factory()->analyze($paths);

            /** @var list<string> $rules */
            $rules = [];
            foreach ($issues as $issue) {
                if ($issue instanceof Issue) {
                    $rules[] = $issue->rule;
                }
            }

            if ($expectedRule === null) {
                if ($issues !== []) {
                    $falsePositives++;
                    $failures[] = $id . ' (FP: ' . implode(',', $rules) . ')';
                }
            } elseif (in_array($expectedRule, $rules, true)) {
                $truePositives++;
            } else {
                $falseNegatives++;
                $failures[] = $id . ' (FN: missing ' . $expectedRule . ')';
            }
        }

        $precision = $truePositives + $falsePositives > 0
            ? (float) $truePositives / ($truePositives + $falsePositives)
            : 1.0;
        $recall = $truePositives + $falseNegatives > 0
            ? (float) $truePositives / ($truePositives + $falseNegatives)
            : 1.0;

        fwrite(
            STDERR,
            sprintf(
                "\n[metrics] cases=%d TP=%d FP=%d FN=%d precision=%.3f recall=%.3f\n",
                $truePositives + $falsePositives + $falseNegatives,
                $truePositives,
                $falsePositives,
                $falseNegatives,
                $precision,
                $recall
            )
        );

        self::assertSame([], $failures, 'Corpus failures: ' . implode('; ', $failures));
        self::assertSame(1.0, $precision);
        self::assertSame(1.0, $recall);
    }

    /**
     * @param array<string, string> $files relPath => content
     * @return list<string> absolute paths
     */
    private function materialize(array $files): array
    {
        $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-metrics-' . uniqid('', true);
        $paths = [];
        foreach ($files as $rel => $content) {
            $path = $dir . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $rel);
            @mkdir(dirname($path), 0777, true);
            file_put_contents($path, $content);
            $paths[] = $path;
        }

        return $paths;
    }
}
