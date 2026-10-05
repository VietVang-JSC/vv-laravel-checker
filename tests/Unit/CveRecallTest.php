<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Tests\Unit;

use Closure;
use PHPUnit\Framework\TestCase;
use Rampart\QualityChecker\Analyzers\Laravel\MigrationAnalyzer;
use Rampart\QualityChecker\Analyzers\Owasp\OwaspBladeXssAnalyzer;
use Rampart\QualityChecker\Analyzers\Owasp\OwaspCommandInjectionAnalyzer;
use Rampart\QualityChecker\Analyzers\Owasp\OwaspOpenRedirectAnalyzer;
use Rampart\QualityChecker\Analyzers\Owasp\OwaspPathTraversalAnalyzer;
use Rampart\QualityChecker\Analyzers\Owasp\OwaspSsrfAnalyzer;
use Rampart\QualityChecker\Analyzers\Owasp\OwaspSstiAnalyzer;
use Rampart\QualityChecker\Analyzers\Owasp\OwaspXxeAnalyzer;
use Rampart\QualityChecker\Analyzers\Security\HardcodedSecretAnalyzer;
use Rampart\QualityChecker\Analyzers\Security\InsecureHashAnalyzer;
use Rampart\QualityChecker\Analyzers\Security\MassAssignmentAnalyzer;
use Rampart\QualityChecker\Analyzers\Security\SqlInjectionAnalyzer;
use Rampart\QualityChecker\Analyzers\Security\UnsafeEvalAnalyzer;
use Rampart\QualityChecker\Analyzers\Security\UnsafeDeserializationAnalyzer;

/**
 * Recall floor: 30 real-world CVE injection shapes.
 *
 * Each case is a single vulnerable file that *must* be flagged. The suite
 * asserts >=90% recall (27/30) — a single analyzer regression that silences
 * a whole class (e.g. SSRF via curl, or mass assignment) drops the floor
 * visibly instead of hiding behind the 1.0 aggregate of AnalyzerMetricsTest.
 *
 * Unlike AnalyzerMetricsTest (precision+recall on labeled TN/TP pairs),
 * this is pure TP recall on injection shapes mined from the 27-project
 * benchmark and public Laravel CVEs. No FP case here — FP is measured by
 * the external sampling tool (tools/sample-findings.php).
 *
 * @see tools/sample-findings.php
 */
final class CveRecallTest extends TestCase
{
    /**
     * @return iterable<string, array{Closure(): object, array<string, string>, string}>
     */
    public static function injections(): iterable
    {
        // SQL injection via orderBy / whereRaw
        yield 'sqli_orderby_request' => [
            static fn (): object => new SqlInjectionAnalyzer(),
            ['app/Http/Controllers/ProductController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse Illuminate\\Support\\Facades\\DB;\nclass ProductController { public function index(\\Illuminate\\Http\\Request \$request) { return DB::table('products')->orderBy(\$request->input('sort'))->get(); } }\n"],
            'SQL_INJECTION',
        ];
        yield 'sqli_whereRaw_concat' => [
            static fn (): object => new SqlInjectionAnalyzer(),
            ['app/Http/Controllers/SearchController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse Illuminate\\Support\\Facades\\DB;\nclass SearchController { public function q(\\Illuminate\\Http\\Request \$request) { return DB::table('t')->whereRaw('x = ' . \$request->input('q'))->get(); } }\n"],
            'SQL_INJECTION',
        ];
        // Mass assignment
        yield 'mass_create_all' => [
            static fn (): object => new MassAssignmentAnalyzer(),
            [
                'app/Http/Controllers/UserController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\User;\nuse Illuminate\\Http\\Request;\nclass UserController { public function store(Request \$r) { return User::create(\$r->all()); } }\n",
                'app/Models/User.php' => "<?php\nnamespace App\\Models;\nclass User extends \\Illuminate\\Database\\Eloquent\\Model { protected \$guarded = []; }\n",
            ],
            'MASS_ASSIGNMENT',
        ];
        // Command injection
        yield 'cmdi_exec_input' => [
            static fn (): object => new OwaspCommandInjectionAnalyzer(),
            ['app/Console/Commands/Run.php' => "<?php\nexec(\$request->input('cmd'));\n"],
            'OWASP_COMMAND_INJECTION',
        ];
        yield 'cmdi_system_input' => [
            static fn (): object => new OwaspCommandInjectionAnalyzer(),
            ['app/Services/Tool.php' => "<?php\nsystem(\$_GET['cmd']);\n"],
            'OWASP_COMMAND_INJECTION',
        ];
        yield 'cmdi_backtick' => [
            static fn (): object => new OwaspCommandInjectionAnalyzer(),
            ['app/Services/Shell.php' => "<?php\n\$out = `ls \$dir`;\n"],
            'OWASP_COMMAND_INJECTION',
        ];
        // SSRF
        yield 'ssrf_file_get_contents_input' => [
            static fn (): object => new OwaspSsrfAnalyzer(),
            ['app/Services/Fetch.php' => "<?php\n\$data = file_get_contents(\$request->input('url'));\n"],
            'OWASP_SSRF',
        ];
        yield 'ssrf_curl_setopt' => [
            static fn (): object => new OwaspSsrfAnalyzer(),
            ['app/Services/Fetch.php' => "<?php\n\$ch=curl_init(); curl_setopt(\$ch, CURLOPT_URL, \$request->input('u'));\n"],
            'OWASP_SSRF',
        ];
        yield 'ssrf_guzzle_request' => [
            static fn (): object => new OwaspSsrfAnalyzer(),
            ['app/Services/Api.php' => "<?php\nclass Api { public function f(\\GuzzleHttp\\Client \$client, \\Illuminate\\Http\\Request \$request){ return \$client->request('GET', \$request->input('url')); } }\n"],
            'OWASP_SSRF',
        ];
        // XSS
        yield 'xss_blade_unescaped_request' => [
            static fn (): object => new OwaspBladeXssAnalyzer(),
            ['resources/views/x.blade.php' => "<div>{!! request('q') !!}</div>\n"],
            'OWASP_BLADE_XSS',
        ];
        yield 'xss_blade_superglobal' => [
            static fn (): object => new OwaspBladeXssAnalyzer(),
            ['resources/views/x.blade.php' => "<div>{!! \$_POST['x'] !!}</div>\n"],
            'OWASP_BLADE_XSS',
        ];
        // SSTI
        yield 'ssti_view_input' => [
            static fn (): object => new OwaspSstiAnalyzer(),
            ['app/Http/Controllers/Page.php' => "<?php\nreturn view(\$request->input('tpl'));\n"],
            'OWASP_SSTI',
        ];
        // Path traversal
        yield 'traversal_include_input' => [
            static fn (): object => new OwaspPathTraversalAnalyzer(),
            ['app/Http/Controllers/File.php' => "<?php\ninclude \$request->input('f');\n"],
            'OWASP_PATH_TRAVERSAL',
        ];
        yield 'traversal_download_input' => [
            static fn (): object => new OwaspPathTraversalAnalyzer(),
            ['app/Http/Controllers/Download.php' => "<?php\nreturn response()->download(storage_path('d/' . \$request->input('file')));\n"],
            'OWASP_PATH_TRAVERSAL',
        ];
        // Open redirect
        yield 'open_redirect_away' => [
            static fn (): object => new OwaspOpenRedirectAnalyzer(),
            ['app/Http/Controllers/Auth.php' => "<?php\nreturn redirect()->away(\$request->input('next'));\n"],
            'OWASP_OPEN_REDIRECT',
        ];
        yield 'open_redirect_to' => [
            static fn (): object => new OwaspOpenRedirectAnalyzer(),
            ['app/Http/Controllers/Auth.php' => "<?php\nreturn redirect()->to(\$request->input('next'));\n"],
            'OWASP_OPEN_REDIRECT',
        ];
        // XXE
        yield 'xxe_simplexml' => [
            static fn (): object => new OwaspXxeAnalyzer(),
            ['app/Services/Xml.php' => "<?php\nsimplexml_load_string(\$request->input('xml'));\n"],
            'OWASP_XXE',
        ];
        // Hardcoded secret
        yield 'secret_sk_live' => [
            static fn (): object => new HardcodedSecretAnalyzer(),
            ['app/Services/Pay.php' => "<?php\nclass Pay { private \$secret='whsec_51H7x8A2eZvKYlo2C4a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s';}\n"],
            'HARDCODED_SECRET',
        ];
        yield 'secret_aws' => [
            static fn (): object => new HardcodedSecretAnalyzer(),
            ['app/Services/Aws.php' => "<?php\nclass Aws { private \$k='AKIAIOSFODNN7EXAMPLEY';}\n"],
            'HARDCODED_SECRET',
        ];
        // Insecure hash
        yield 'hash_md5_password' => [
            static fn (): object => new InsecureHashAnalyzer(),
            ['app/Services/Auth.php' => "<?php\nclass Auth { public function v(string \$password, string \$hash){ return md5(\$password)===\$hash; } }\n"],
            'INSECURE_HASH',
        ];
        // Eval
        yield 'eval_input' => [
            static fn (): object => new UnsafeEvalAnalyzer(),
            ['app/Services/Eval.php' => "<?php\nclass E { public function r(string \$c){ eval(\$c); } }\n"],
            'UNSAFE_EVAL',
        ];
        // Deserialize
        yield 'deser_unserialize_input' => [
            static fn (): object => new UnsafeDeserializationAnalyzer(),
            ['app/Controllers/D.php' => "<?php\nclass D{ public function l(\\Illuminate\\Http\\Request \$r){ return unserialize(\$r->input('d')); } }\n"],
            'UNSAFE_UNSERIALIZE',
        ];
        // Additional high-value injections (remain >90% even if 2-3 miss)
        yield 'sqli_orderby_desc' => [
            static fn (): object => new SqlInjectionAnalyzer(),
            ['app/Http/Controllers/P.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse Illuminate\\Support\\Facades\\DB;\nclass P{ public function i(\\Illuminate\\Http\\Request \$request){ return DB::table('t')->orderByDesc(\$request->input('sort'))->get(); } }\n"],
            'SQL_INJECTION',
        ];
        yield 'cmdi_passthru_input' => [
            static fn (): object => new OwaspCommandInjectionAnalyzer(),
            ['app/Services/P.php' => "<?php\npassthru(\$request->input('cmd'));\n"],
            'OWASP_COMMAND_INJECTION',
        ];
        yield 'ssrf_fopen_input' => [
            static fn (): object => new OwaspSsrfAnalyzer(),
            ['app/Services/F.php' => "<?php\nfopen(\$request->input('url'), 'r');\n"],
            'OWASP_SSRF',
        ];
        yield 'traversal_file_get_contents_var' => [
            static fn (): object => new OwaspPathTraversalAnalyzer(),
            ['app/Services/F2.php' => "<?php\nfile_get_contents(\$request->input('file'));\n"],
            'OWASP_PATH_TRAVERSAL',
        ];
        yield 'xss_blade_js_concat' => [
            static fn (): object => new OwaspBladeXssAnalyzer(),
            ['resources/views/y.blade.php' => "<script>{!! json_encode(\$data) !!}</script>\n"],
            'OWASP_BLADE_XSS',
        ];
        yield 'ssti_blade_render_input' => [
            static fn (): object => new OwaspSstiAnalyzer(),
            ['app/Services/V.php' => "<?php\nreturn \\Illuminate\\Support\\Facades\\Blade::render(\$request->input('tpl'));\n"],
            'OWASP_SSTI',
        ];
        yield 'misconfig_debug_true' => [
            static fn (): object => new \Rampart\QualityChecker\Analyzers\Owasp\OwaspMisconfigurationAnalyzer(),
            ['config/app.php' => "<?php\nreturn ['debug'=>true];\n"],
            'OWASP_MISCONFIGURATION',
        ];
        yield 'secret_ghp' => [
            static fn (): object => new HardcodedSecretAnalyzer(),
            ['app/Services/G.php' => "<?php\nclass G{ private \$t='ghp_1234567890abcdef1234567890abcdef123456';}\n"],
            'HARDCODED_SECRET',
        ];
    }

    /**
     * @param array<string, string> $files
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('injections')]
    public function testInjectionIsFlagged(Closure $factory, array $files, string $expectedRule): void
    {
        $paths = $this->materialize($files);
        $issues = $factory()->analyze($paths);
        $rules = array_map(static fn ($i) => $i->rule, $issues);
        self::assertContains($expectedRule, $rules, 'Recall injection missed — expected ' . $expectedRule);
    }

    public function testRecallFloorIsAtLeastNinetyPercent(): void
    {
        $total = 0;
        $found = 0;
        $missed = [];
        foreach (self::injections() as $id => [$factory, $files, $expectedRule]) {
            $total++;
            $paths = $this->materialize($files);
            $issues = $factory()->analyze($paths);
            $rules = array_map(static fn ($i) => $i->rule, $issues);
            if (in_array($expectedRule, $rules, true)) {
                $found++;
            } else {
                $missed[] = $id . ':' . $expectedRule;
            }
        }
        $recall = $total > 0 ? $found / $total : 1.0;
        fwrite(STDERR, sprintf("\n[recall] %d/%d (%.1f%%) missed: %s\n", $found, $total, $recall * 100, implode(', ', $missed)));
        self::assertGreaterThanOrEqual(0.90, $recall, 'Recall floor 90% breached — missed: ' . implode(', ', $missed));
    }

    /**
     * @param array<string, string> $files
     * @return list<string>
     */
    private function materialize(array $files): array
    {
        $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'qc-recall-' . uniqid('', true);
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
