<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Tests\Unit;

use Closure;
use PHPUnit\Framework\TestCase;
use VietVang\QualityChecker\Analyzers\AbstractAnalyzer;
use VietVang\QualityChecker\Analyzers\Laravel\MigrationAnalyzer;
use VietVang\QualityChecker\Analyzers\Laravel\RouteValidationAnalyzer;
use VietVang\QualityChecker\Analyzers\Owasp\OwaspAccessControlAnalyzer;
use VietVang\QualityChecker\Analyzers\Owasp\OwaspBladeXssAnalyzer;
use VietVang\QualityChecker\Analyzers\Owasp\OwaspCommandInjectionAnalyzer;
use VietVang\QualityChecker\Analyzers\Owasp\OwaspMisconfigurationAnalyzer;
use VietVang\QualityChecker\Analyzers\Owasp\OwaspOpenRedirectAnalyzer;
use VietVang\QualityChecker\Analyzers\Owasp\OwaspPathTraversalAnalyzer;
use VietVang\QualityChecker\Analyzers\Owasp\OwaspSsrfAnalyzer;
use VietVang\QualityChecker\Analyzers\Owasp\OwaspSstiAnalyzer;
use VietVang\QualityChecker\Analyzers\Owasp\OwaspXxeAnalyzer;
use VietVang\QualityChecker\Analyzers\Security\HardcodedSecretAnalyzer;
use VietVang\QualityChecker\Analyzers\Security\InsecureHashAnalyzer;
use VietVang\QualityChecker\Analyzers\Security\MassAssignmentAnalyzer;
use VietVang\QualityChecker\Analyzers\Security\SqlInjectionAnalyzer;
use VietVang\QualityChecker\Analyzers\Security\UnsafeDeserializationAnalyzer;
use VietVang\QualityChecker\Analyzers\Security\UnsafeEvalAnalyzer;
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
     * @return iterable<string, array{Closure(): (AbstractAnalyzer|InsecureHashAnalyzer|UnsafeDeserializationAnalyzer|UnsafeEvalAnalyzer|HardcodedSecretAnalyzer|MassAssignmentAnalyzer), array<string, string>, string|null}>
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
        yield 'bac_fp_can_method' => [
            static fn (): AbstractAnalyzer => new OwaspAccessControlAnalyzer(),
            [
                'app/Http/Controllers/PostController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse Illuminate\\Http\\Request;\nclass PostController extends Controller {\n    public function update(Request \$request, \$id) {\n        \$post = Post::findOrFail(\$id);\n        \$request->user()->can('update', \$post);\n        \$post->save();\n    }\n}\n",
            ],
            null,
        ];
        yield 'bac_fp_provider_group_middleware' => [
            static fn (): AbstractAnalyzer => new OwaspAccessControlAnalyzer(),
            [
                'app/Http/Controllers/Api/BackupController.php' => "<?php\nnamespace App\\Http\\Controllers\\Api;\nclass BackupController extends Controller {\n    public function store() {\n        \$this->model->save();\n    }\n}\n",
                'routes/api.php' => "<?php\nuse Illuminate\\Support\\Facades\\Route;\nRoute::post('/backup', 'App\\Http\\Controllers\\Api\\BackupController@store');\n",
                'app/Providers/RouteServiceProvider.php' => "<?php\nnamespace App\\Providers;\nuse Illuminate\\Support\\Facades\\Route;\nclass RouteServiceProvider {\n    public function boot(): void {\n        Route::group(['middleware' => 'auth:api', 'prefix' => 'api'], function () {\n            require base_path('routes/api.php');\n        });\n    }\n}\n",
            ],
            null,
        ];
        yield 'bac_fp_extra_middleware' => [
            static fn (): AbstractAnalyzer => new OwaspAccessControlAnalyzer(true, ['extra_middleware' => ['verified-staff']]),
            [
                'app/Http/Controllers/BackupController.php' => "<?php\nnamespace App\\Http\\Controllers;\nclass BackupController extends Controller {\n    public function store() {\n        \$this->model->save();\n    }\n}\n",
                'routes/web.php' => "<?php\nuse Illuminate\\Support\\Facades\\Route;\nRoute::post('/backup', 'App\\Http\\Controllers\\BackupController@store')->middleware('verified-staff');\n",
            ],
            null,
        ];
        yield 'bac_tp_unknown_middleware' => [
            static fn (): AbstractAnalyzer => new OwaspAccessControlAnalyzer(true, ['extra_middleware' => ['verified-staff']]),
            [
                'app/Http/Controllers/BackupController.php' => "<?php\nnamespace App\\Http\\Controllers;\nclass BackupController extends Controller {\n    public function store() {\n        \$this->model->save();\n    }\n}\n",
                'routes/web.php' => "<?php\nuse Illuminate\\Support\\Facades\\Route;\nRoute::post('/backup', 'App\\Http\\Controllers\\BackupController@store')->middleware('throttle:forms');\n",
            ],
            'OWASP_BROKEN_ACCESS_CONTROL',
        ];
        yield 'validation_fp_use_imported_formrequest' => [
            static fn (): AbstractAnalyzer => new RouteValidationAnalyzer(),
            ['app/Api/V1/Controllers/AccountController.php' => "<?php\nnamespace App\\Api\\V1\\Controllers;\nuse App\\Api\\V1\\Requests\\StoreRequest;\nclass AccountController extends Controller {\n    public function store(StoreRequest \$request) {\n        return \$this->repository->store(\$request->getAllAccountData());\n    }\n}\n"],
            null,
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
        yield 'cmd_tp_backtick_input' => [
            static fn (): AbstractAnalyzer => new OwaspCommandInjectionAnalyzer(),
            ['app/Services/ListingService.php' => "<?php\n\$out = `ls \$dir`;\n"],
            'OWASP_COMMAND_INJECTION',
        ];
        yield 'cmd_fp_backtick_literal' => [
            static fn (): AbstractAnalyzer => new OwaspCommandInjectionAnalyzer(),
            ['app/Services/ListingService.php' => "<?php\n\$out = `ls -la`;\n"],
            null,
        ];
        yield 'cmd_fp_private_helper_literal' => [
            static fn (): AbstractAnalyzer => new OwaspCommandInjectionAnalyzer(),
            ['app/Http/Controllers/EdgeManager.php' => "<?php\nclass EdgeManager {\n    public function handle(string \$action): void {\n        if (\$action === 'start') { \$this->controlServices('start'); }\n    }\n    private function controlServices(string \$cmd): void {\n        exec(\"nssm \$cmd svc 2>&1\", \$output, \$code);\n    }\n}\n"],
            null,
        ];
        yield 'cmd_fp_foreach_const' => [
            static fn (): AbstractAnalyzer => new OwaspCommandInjectionAnalyzer(),
            ['app/Http/Controllers/EdgeManager.php' => "<?php\nclass EdgeManager {\n    private const SERVICES = ['svc-a'];\n    private function controlServices(string \$cmd): void {\n        foreach (self::SERVICES as \$svc) {\n            exec(\"nssm \$cmd \$svc 2>&1\", \$output, \$code);\n        }\n    }\n    public function start(): void {\n        \$this->controlServices('start');\n    }\n}\n"],
            null,
        ];
        yield 'cmd_fp_env_escaped' => [
            static fn (): AbstractAnalyzer => new OwaspCommandInjectionAnalyzer(),
            ['app/Services/PdfService.php' => "<?php\nclass PdfService {\n    public function render(string \$pdfPath): void {\n        \$input = escapeshellarg(\$pdfPath);\n        \$bin = env('IMAGE_MAGICK_CLI', 'convert');\n        exec(\"deny 203 {\$input}\", \$o, \$s);\n    }\n}\n"],
            null,
        ];
        yield 'cmd_tp_mail_fifth_arg' => [
            static fn (): AbstractAnalyzer => new OwaspCommandInjectionAnalyzer(),
            ['app/Services/MailService.php' => "<?php\nmail(\$to, \$subject, \$message, \$headers, \$extra);\n"],
            'OWASP_COMMAND_INJECTION',
        ];
        yield 'cmd_fp_mail_no_fifth_arg' => [
            static fn (): AbstractAnalyzer => new OwaspCommandInjectionAnalyzer(),
            ['app/Services/MailService.php' => "<?php\nmail(\$to, \$subject, \$message, \$headers);\n"],
            null,
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
        yield 'ssrf_fp_sprintf_fixed_host_var' => [
            static fn (): AbstractAnalyzer => new OwaspSsrfAnalyzer(),
            ['src/Tools/Downloader.php' => "<?php\n\$url = sprintf('https://github.com/aquasecurity/trivy/releases/download/v%s/t.tgz', \$version);\n\$fp = fopen(\$url, 'rb');\n"],
            null,
        ];
        yield 'ssrf_fp_file_var' => [
            static fn (): AbstractAnalyzer => new OwaspSsrfAnalyzer(),
            ['src/Analyzers/Reader.php' => "<?php\nclass Reader {\n    protected function readFile(string \$path): string {\n        return (string) file_get_contents(\$path);\n    }\n}\n"],
            null,
        ];
        yield 'ssrf_tp_guzzle_request_second_arg' => [
            static fn (): AbstractAnalyzer => new OwaspSsrfAnalyzer(),
            ['app/Services/ApiClient.php' => "<?php\nclass ApiClient {\n    public function call(string \$method, string \$endpoint): array {\n        \$response = \$client->request(\$method, \$endpoint, []);\n        return [];\n    }\n}\n"],
            'OWASP_SSRF',
        ];
        yield 'ssrf_fp_deploytime_url' => [
            static fn (): AbstractAnalyzer => new OwaspSsrfAnalyzer(),
            ['app/Http/Controllers/PrinterController.php' => "<?php\nclass PrinterController extends Controller {\n    public function list() {\n        \$res = \$client->request('GET', rtrim(env('API_URL'), '/') . '/api/x', []);\n        return [];\n    }\n}\n"],
            null,
        ];
        yield 'ssrf_tp_nullsafe_client_call' => [
            static fn (): AbstractAnalyzer => new OwaspSsrfAnalyzer(),
            ['app/Services/ExternalService.php' => "<?php\n\$response = \$client?->get(\$request->input('target'));\n"],
            'OWASP_SSRF',
        ];
        yield 'ssrf_tp_named_url_argument' => [
            static fn (): AbstractAnalyzer => new OwaspSsrfAnalyzer(),
            ['app/Services/ExternalService.php' => "<?php\n\$response = \$client->get(url: \$request->input('target'));\n"],
            'OWASP_SSRF',
        ];
        yield 'ssrf_tp_curl_setopt_url' => [
            static fn (): AbstractAnalyzer => new OwaspSsrfAnalyzer(),
            ['app/Services/ExternalService.php' => "<?php\n\$ch = curl_init();\ncurl_setopt(\$ch, CURLOPT_URL, \$request->input('target'));\n"],
            'OWASP_SSRF',
        ];
        yield 'ssrf_tp_copy_url' => [
            static fn (): AbstractAnalyzer => new OwaspSsrfAnalyzer(),
            ['app/Services/ExternalService.php' => "<?php\ncopy(\$request->input('src'), \$dest);\n"],
            'OWASP_SSRF',
        ];
        yield 'ssrf_tp_readfile_url' => [
            static fn (): AbstractAnalyzer => new OwaspSsrfAnalyzer(),
            ['app/Services/ExternalService.php' => "<?php\nreadfile(\$request->input('file'));\n"],
            'OWASP_SSRF',
        ];
        yield 'ssrf_fp_file_local_path' => [
            static fn (): AbstractAnalyzer => new OwaspSsrfAnalyzer(),
            ['app/Services/ExternalService.php' => "<?php\n\$lines = file(\$path);\n"],
            null,
        ];
        yield 'ssrf_tp_fsockopen_host' => [
            static fn (): AbstractAnalyzer => new OwaspSsrfAnalyzer(),
            ['app/Services/ExternalService.php' => "<?php\n\$fp = fsockopen(\$host, 80);\n"],
            'OWASP_SSRF',
        ];
        yield 'ssrf_fp_fsockopen_literal' => [
            static fn (): AbstractAnalyzer => new OwaspSsrfAnalyzer(),
            ['app/Services/ExternalService.php' => "<?php\n\$fp = fsockopen('localhost', 80);\n"],
            null,
        ];
        yield 'ssrf_fp_glob_loop' => [
            static fn (): AbstractAnalyzer => new OwaspSsrfAnalyzer(),
            ['app/Console/Commands/MoveUploads.php' => "<?php\n\$logos = glob('public/uploads/*.*');\nforeach (\$logos as \$logo) {\n    \$contents = file_get_contents(\$logo);\n}\n"],
            null,
        ];

        // --- SSTI ---
        yield 'ssti_tp_input_var' => [
            static fn (): AbstractAnalyzer => new OwaspSstiAnalyzer(),
            ['app/Http/Controllers/PageController.php' => "<?php\n\$viewName = \$request->input('template');\nreturn view(\$viewName);\n"],
            'OWASP_SSTI',
        ];
        yield 'ssti_fp_literal_var' => [
            static fn (): AbstractAnalyzer => new OwaspSstiAnalyzer(),
            ['app/Http/Controllers/ExerciseController.php' => "<?php\nnamespace App\\Http\\Controllers;\nclass ExerciseController extends Controller {\n    public function edit() {\n        \$viewName = 'backend.exercise.edit_catalog';\n        return view(\$viewName);\n    }\n}\n"],
            null,
        ];
        yield 'ssti_fp_concat_literals' => [
            static fn (): AbstractAnalyzer => new OwaspSstiAnalyzer(),
            ['app/Http/Controllers/PosController.php' => "<?php\nnamespace App\\Http\\Controllers;\nclass PosController extends Controller {\n    public function index() {\n        \$industry = 2;\n        \$viewName = 'front.pos.pos_type_' . \$industry . '.pos_new';\n        return view(\$viewName);\n    }\n}\n"],
            null,
        ];
        yield 'ssti_fp_class_const_concat' => [
            static fn (): AbstractAnalyzer => new OwaspSstiAnalyzer(),
            ['app/Filament/OrderItemsTable.php' => "<?php\nuse Filament\\Support\\Facades\\Blade;\nclass OrderItemsTable {\n    public static function cols(): array {\n        return [Blade::render('<x-icon style=\"' . \\App\\Color::Gray[400] . '\"/>')];\n    }\n}\n"],
            null,
        ];
        yield 'ssti_fp_view_registry' => [
            static fn (): AbstractAnalyzer => new OwaspSstiAnalyzer(),
            ['app/Abstracts/Report.php' => "<?php\nnamespace App;\nclass Report {\n    protected \$views = ['show' => 'reports.show'];\n    public function show() {\n        return view(\$this->views['show']);\n    }\n}\n"],
            null,
        ];
        yield 'ssti_tp_view_facade_make' => [
            static fn (): AbstractAnalyzer => new OwaspSstiAnalyzer(),
            ['app/Http/Controllers/PageController.php' => "<?php\nreturn \\Illuminate\\Support\\Facades\\View::make(\$template);\n"],
            'OWASP_SSTI',
        ];
        yield 'ssti_fp_view_facade_make_literal' => [
            static fn (): AbstractAnalyzer => new OwaspSstiAnalyzer(),
            ['app/Http/Controllers/PageController.php' => "<?php\nreturn \\Illuminate\\Support\\Facades\\View::make('pages.home');\n"],
            null,
        ];
        yield 'ssti_tp_view_composer_tainted' => [
            static fn (): AbstractAnalyzer => new OwaspSstiAnalyzer(),
            ['app/Providers/ViewServiceProvider.php' => "<?php\n\\View::composer(\$view, function (\$v) {});\n"],
            'OWASP_SSTI',
        ];
        yield 'ssti_fp_view_composer_literal' => [
            static fn (): AbstractAnalyzer => new OwaspSstiAnalyzer(),
            ['app/Providers/ViewServiceProvider.php' => "<?php\n\\View::composer('admin.*', function (\$v) {});\n"],
            null,
        ];
        yield 'ssti_fp_in_array_allow_list' => [
            static fn (): AbstractAnalyzer => new OwaspSstiAnalyzer(),
            ['app/Http/Controllers/ModalController.php' => "<?php\nclass ModalController {\n    public function show(string \$type) {\n        \$allowed = ['a', 'b'];\n        if (in_array(\$type, \$allowed)) {\n            return view(\"x.{\$type}\");\n        }\n        abort(404);\n    }\n}\n"],
            null,
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
        yield 'xxe_tp_xmlreader_open' => [
            static fn (): AbstractAnalyzer => new OwaspXxeAnalyzer(),
            ['app/Services/FeedParser.php' => "<?php\n\$xml = XMLReader::open(\$uri);\n"],
            'OWASP_XXE',
        ];
        yield 'xxe_tp_reader_open_method' => [
            static fn (): AbstractAnalyzer => new OwaspXxeAnalyzer(),
            ['app/Services/FeedParser.php' => "<?php\n\$reader = new XMLReader();\n\$reader->open(\$path);\n"],
            'OWASP_XXE',
        ];
        yield 'xxe_tp_noent_option' => [
            static fn (): AbstractAnalyzer => new OwaspXxeAnalyzer(),
            ['app/Services/FeedParser.php' => "<?php\n\$xml = simplexml_load_string(\$raw, 'SimpleXMLElement', LIBXML_NOENT);\n"],
            'OWASP_XXE',
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
        yield 'hash_tp_weak_hash_fn' => [
            static fn (): InsecureHashAnalyzer => new InsecureHashAnalyzer(),
            ['app/Services/AuthService.php' => "<?php\nnamespace App\\Services;\nclass AuthService {\n    public function verify(string \$password): bool {\n        return hash('md5', \$password) === \$this->storedHash;\n    }\n}\n"],
            'INSECURE_HASH',
        ];
        yield 'hash_fp_strong_hash_fn' => [
            static fn (): InsecureHashAnalyzer => new InsecureHashAnalyzer(),
            ['app/Services/TokenService.php' => "<?php\nnamespace App\\Services;\nclass TokenService {\n    public function fingerprint(string \$password): string {\n        return hash('sha256', \$password);\n    }\n}\n"],
            null,
        ];
        yield 'hash_tp_mtrand_otp' => [
            static fn (): InsecureHashAnalyzer => new InsecureHashAnalyzer(),
            ['app/Services/OtpService.php' => "<?php\nnamespace App\\Services;\nclass OtpService {\n    public function generate(): int {\n        \$otp = mt_rand(100000, 999999);\n        return \$otp;\n    }\n}\n"],
            'INSECURE_HASH',
        ];
        yield 'hash_fp_mtrand_counter' => [
            static fn (): InsecureHashAnalyzer => new InsecureHashAnalyzer(),
            ['app/Services/RetryService.php' => "<?php\nnamespace App\\Services;\nclass RetryService {\n    public function attempts(): int {\n        \$tries = mt_rand(1, 5);\n        return \$tries;\n    }\n}\n"],
            null,
        ];
        yield 'hash_fp_random_int_otp' => [
            static fn (): InsecureHashAnalyzer => new InsecureHashAnalyzer(),
            ['app/Services/OtpService.php' => "<?php\nnamespace App\\Services;\nclass OtpService {\n    public function generate(): int {\n        \$otp = random_int(100000, 999999);\n        return \$otp;\n    }\n}\n"],
            null,
        ];
        yield 'eval_fp_preg_guarded' => [
            static fn (): UnsafeEvalAnalyzer => new UnsafeEvalAnalyzer(),
            ['app/Services/MathService.php' => "<?php\nnamespace App\\Services;\nclass MathService {\n    public function calc(string \$quantity): float {\n        if (!preg_match('/^[0-9]+$/', \$quantity)) {\n            throw new \\InvalidArgumentException('bad');\n        }\n        return (float) eval('return ' . \$quantity . ';');\n    }\n}\n"],
            null,
        ];
        yield 'eval_tp_call_user_func_input' => [
            static fn (): UnsafeEvalAnalyzer => new UnsafeEvalAnalyzer(),
            ['app/Services/ActionService.php' => "<?php\nnamespace App\\Services;\nclass ActionService {\n    public function run(\\Illuminate\\Http\\Request \$request): void {\n        call_user_func(\$request->input('action'));\n    }\n}\n"],
            'UNSAFE_EVAL',
        ];
        yield 'eval_fp_call_user_func_literal' => [
            static fn (): UnsafeEvalAnalyzer => new UnsafeEvalAnalyzer(),
            ['app/Services/ActionService.php' => "<?php\nnamespace App\\Services;\nclass ActionService {\n    public function run(\\Illuminate\\Http\\Request \$request): void {\n        call_user_func([\$this, 'handle'], \$request->input('x'));\n    }\n}\n"],
            null,
        ];
        yield 'eval_fp_this_callback_property' => [
            static fn (): UnsafeEvalAnalyzer => new UnsafeEvalAnalyzer(),
            ['app/Services/ImportService.php' => "<?php\nnamespace App\\Services;\nclass ImportService {\n    protected \$progressCallback;\n    public function run(): void {\n        if (\$this->progressCallback) {\n            call_user_func(\$this->progressCallback, 1);\n        }\n    }\n}\n"],
            null,
        ];
        yield 'deser_tp_yaml_parse_input' => [
            static fn (): UnsafeDeserializationAnalyzer => new UnsafeDeserializationAnalyzer(),
            ['app/Services/ImportService.php' => "<?php\nnamespace App\\Services;\nclass ImportService {\n    public function run(\\Illuminate\\Http\\Request \$request): array {\n        return yaml_parse(\$request->input('doc'));\n    }\n}\n"],
            'UNSAFE_UNSERIALIZE',
        ];
        yield 'deser_fp_allowed_classes_false' => [
            static fn (): UnsafeDeserializationAnalyzer => new UnsafeDeserializationAnalyzer(),
            ['app/Services/SessionService.php' => "<?php\nnamespace App\\Services;\nclass SessionService {\n    public function hydrate(\\Illuminate\\Http\\Request \$request): array {\n        return unserialize(\$request->input('data'), ['allowed_classes' => false]);\n    }\n}\n"],
            null,
        ];
        yield 'sqli_tp_orderby_request' => [
            static fn (): AbstractAnalyzer => new SqlInjectionAnalyzer(),
            ['app/Http/Controllers/ProductController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse Illuminate\\Support\\Facades\\DB;\nclass ProductController {\n    public function index(\\Illuminate\\Http\\Request \$request) {\n        return DB::table('products')->orderBy(\$request->input('sort'))->get();\n    }\n}\n"],
            'SQL_INJECTION',
        ];
        yield 'sqli_fp_orderby_literal' => [
            static fn (): AbstractAnalyzer => new SqlInjectionAnalyzer(),
            ['app/Http/Controllers/ProductController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse Illuminate\\Support\\Facades\\DB;\nclass ProductController {\n    public function index() {\n        return DB::table('products')->orderBy('created_at')->get();\n    }\n}\n"],
            null,
        ];
        yield 'secret_fp_option_const' => [
            static fn (): HardcodedSecretAnalyzer => new HardcodedSecretAnalyzer(),
            ['app/Console/Commands/Install.php' => "<?php\nnamespace App\\Console\\Commands;\nclass Install {\n    const OPT_DB_PASSWORD = 'db-password';\n}\n"],
            null,
        ];
        yield 'secret_tp_env_default' => [
            static fn (): HardcodedSecretAnalyzer => new HardcodedSecretAnalyzer(),
            ['config/services.php' => "<?php\nreturn ['key' => env('PAYMENT_API_KEY', 'aB3x9QwE7rT2yU4iO6p')];\n"],
            'HARDCODED_SECRET',
        ];
        yield 'secret_fp_env_placeholder_default' => [
            static fn (): HardcodedSecretAnalyzer => new HardcodedSecretAnalyzer(),
            ['config/app.php' => "<?php\nreturn ['url' => env('APP_URL', 'http://localhost'), 'key' => env('APP_KEY', '')];\n"],
            null,
        ];

        // --- Mass assignment ---
        yield 'mass_tp_update_or_create' => [
            static fn (): MassAssignmentAnalyzer => new MassAssignmentAnalyzer(),
            [
                'app/Http/Controllers/OrderController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\Order;\nuse Illuminate\\Http\\Request;\nclass OrderController {\n    public function store(Request \$request) {\n        return Order::updateOrCreate(['code' => 'x'], \$request->all());\n    }\n}\n",
                'app/Models/Order.php' => "<?php\nnamespace App\\Models;\nclass Order extends \\Illuminate\\Database\\Eloquent\\Model {}\n",
            ],
            'MASS_ASSIGNMENT',
        ];
        yield 'mass_tp_empty_guarded' => [
            static fn (): MassAssignmentAnalyzer => new MassAssignmentAnalyzer(),
            [
                'app/Http/Controllers/OrderController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\Order;\nuse Illuminate\\Http\\Request;\nclass OrderController extends Controller {\n    public function store(Request \$request) {\n        return Order::create(\$request->all());\n    }\n}\n",
                'app/Models/Order.php' => "<?php\nnamespace App\\Models;\nclass Order extends \\Illuminate\\Database\\Eloquent\\Model {\n    protected \$guarded = [];\n}\n",
            ],
            'MASS_ASSIGNMENT',
        ];
        yield 'mass_fp_guarded' => [
            static fn (): MassAssignmentAnalyzer => new MassAssignmentAnalyzer(),
            [
                'app/Http/Controllers/OrderController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\Order;\nuse Illuminate\\Http\\Request;\nclass OrderController extends Controller {\n    public function store(Request \$request) {\n        return Order::create(\$request->all());\n    }\n}\n",
                'app/Models/Order.php' => "<?php\nnamespace App\\Models;\nclass Order extends \\Illuminate\\Database\\Eloquent\\Model {\n    protected \$guarded = ['id'];\n}\n",
            ],
            null,
        ];
        yield 'mass_tp_unguard' => [
            static fn (): MassAssignmentAnalyzer => new MassAssignmentAnalyzer(),
            [
                'app/Providers/AppServiceProvider.php' => "<?php\nnamespace App\\Providers;\nuse App\\Models\\User;\nclass AppServiceProvider {\n    public function boot(): void {\n        User::unguard();\n    }\n}\n",
                'app/Models/User.php' => "<?php\nnamespace App\\Models;\nclass User extends \\Illuminate\\Database\\Eloquent\\Model {}\n",
            ],
            'MASS_ASSIGNMENT',
        ];
        yield 'mass_fp_reguard' => [
            static fn (): MassAssignmentAnalyzer => new MassAssignmentAnalyzer(),
            [
                'app/Providers/AppServiceProvider.php' => "<?php\nnamespace App\\Providers;\nuse App\\Models\\User;\nclass AppServiceProvider {\n    public function boot(): void {\n        User::unguard(false);\n    }\n}\n",
                'app/Models/User.php' => "<?php\nnamespace App\\Models;\nclass User extends \\Illuminate\\Database\\Eloquent\\Model {}\n",
            ],
            null,
        ];
        yield 'mass_tp_forcefill_request' => [
            static fn (): MassAssignmentAnalyzer => new MassAssignmentAnalyzer(),
            [
                'app/Http/Controllers/OrderController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\Order;\nuse Illuminate\\Http\\Request;\nclass OrderController {\n    public function update(Request \$request, Order \$order) {\n        \$order->forceFill(\$request->all());\n    }\n}\n",
                'app/Models/Order.php' => "<?php\nnamespace App\\Models;\nclass Order extends \\Illuminate\\Database\\Eloquent\\Model {\n    protected \$fillable = ['name'];\n}\n",
            ],
            'MASS_ASSIGNMENT',
        ];
        yield 'mass_fp_forcefill_literal' => [
            static fn (): MassAssignmentAnalyzer => new MassAssignmentAnalyzer(),
            [
                'app/Http/Controllers/OrderController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Models\\Order;\nclass OrderController {\n    public function update(Order \$order) {\n        \$order->forceFill(['role' => 'admin']);\n    }\n}\n",
                'app/Models/Order.php' => "<?php\nnamespace App\\Models;\nclass Order extends \\Illuminate\\Database\\Eloquent\\Model {}\n",
            ],
            null,
        ];
        yield 'mass_tp_custom_model_dir' => [
            static fn (): MassAssignmentAnalyzer => new MassAssignmentAnalyzer(['models_dirs' => ['app/Domain/Shop/Models']]),
            [
                'app/Http/Controllers/OrderController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Domain\\Shop\\Models\\Order;\nuse Illuminate\\Http\\Request;\nclass OrderController {\n    public function store(Request \$request) {\n        return Order::create(\$request->all());\n    }\n}\n",
                'app/Domain/Shop/Models/Order.php' => "<?php\nnamespace App\\Domain\\Shop\\Models;\nclass Order extends \\Illuminate\\Database\\Eloquent\\Model {}\n",
            ],
            'MASS_ASSIGNMENT',
        ];
        yield 'mass_fp_custom_dir_default_options' => [
            static fn (): MassAssignmentAnalyzer => new MassAssignmentAnalyzer(),
            [
                'app/Http/Controllers/OrderController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse App\\Domain\\Shop\\Models\\Order;\nuse Illuminate\\Http\\Request;\nclass OrderController {\n    public function store(Request \$request) {\n        return Order::create(\$request->all());\n    }\n}\n",
                'app/Domain/Shop/Models/Order.php' => "<?php\nnamespace App\\Domain\\Shop\\Models;\nclass Order extends \\Illuminate\\Database\\Eloquent\\Model {}\n",
            ],
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
        yield 'mig_tp_raw_drop_table' => [
            static fn (): AbstractAnalyzer => new MigrationAnalyzer(),
            ['database/migrations/2026_01_01_w.php' => "<?php\nreturn new class extends Migration {\n    public function up(): void { DB::statement('DROP TABLE IF EXISTS sessions'); }\n    public function down(): void { }\n};\n"],
            'MIGRATION_DESTRUCTIVE_UP',
        ];
        yield 'mig_fp_raw_truncate_restored' => [
            static fn (): AbstractAnalyzer => new MigrationAnalyzer(),
            ['database/migrations/2026_01_01_v.php' => "<?php\nreturn new class extends Migration {\n    public function up(): void { DB::unprepared('TRUNCATE TABLE temp_import'); }\n    public function down(): void { Schema::create('temp_import', function (Blueprint \$t) { \$t->id(); }); }\n};\n"],
            null,
        ];
        yield 'mig_tp_raw_alter_drop_column' => [
            static fn (): AbstractAnalyzer => new MigrationAnalyzer(),
            ['database/migrations/2026_01_01_u.php' => "<?php\nreturn new class extends Migration {\n    public function up(): void { DB::statement('ALTER TABLE users DROP COLUMN ssn'); }\n    public function down(): void { }\n};\n"],
            'MIGRATION_DESTRUCTIVE_UP',
        ];
        yield 'mig_fp_raw_alter_drop_restored' => [
            static fn (): AbstractAnalyzer => new MigrationAnalyzer(),
            ['database/migrations/2026_01_01_t.php' => "<?php\nreturn new class extends Migration {\n    public function up(): void { DB::statement('ALTER TABLE users DROP COLUMN ssn'); }\n    public function down(): void { Schema::table('users', function (Blueprint \$t) { \$t->string('ssn')->nullable(); }); }\n};\n"],
            null,
        ];

        // --- Open redirect ---
        yield 'openredirect_tp_redirect_input' => [
            static fn (): AbstractAnalyzer => new OwaspOpenRedirectAnalyzer(),
            ['app/Http/Controllers/AuthController.php' => "<?php\nreturn redirect(\$request->input('next'));\n"],
            'OWASP_OPEN_REDIRECT',
        ];
        yield 'openredirect_tp_facade_away_var' => [
            static fn (): AbstractAnalyzer => new OwaspOpenRedirectAnalyzer(),
            ['app/Http/Controllers/AuthController.php' => "<?php\nuse Illuminate\\Support\\Facades\\Redirect;\nreturn Redirect::away(\$url);\n"],
            'OWASP_OPEN_REDIRECT',
        ];
        yield 'openredirect_tp_concat_target' => [
            static fn (): AbstractAnalyzer => new OwaspOpenRedirectAnalyzer(),
            ['app/Http/Controllers/AuthController.php' => "<?php\nreturn redirect('/go?next=' . \$next);\n"],
            'OWASP_OPEN_REDIRECT',
        ];
        yield 'openredirect_fp_route' => [
            static fn (): AbstractAnalyzer => new OwaspOpenRedirectAnalyzer(),
            ['app/Http/Controllers/AuthController.php' => "<?php\nreturn redirect()->route('home');\n"],
            null,
        ];
        yield 'openredirect_fp_back' => [
            static fn (): AbstractAnalyzer => new OwaspOpenRedirectAnalyzer(),
            ['app/Http/Controllers/AuthController.php' => "<?php\nreturn redirect()->back();\n"],
            null,
        ];
        yield 'openredirect_fp_config_concat' => [
            static fn (): AbstractAnalyzer => new OwaspOpenRedirectAnalyzer(),
            ['app/Http/Controllers/AuthController.php' => "<?php\nreturn redirect(config('app.url') . '/done');\n"],
            null,
        ];
        yield 'openredirect_fp_config_var' => [
            static fn (): AbstractAnalyzer => new OwaspOpenRedirectAnalyzer(),
            ['app/Http/Controllers/Admin/LoginCuserController.php' => "<?php\nnamespace App\\Http\\Controllers\\Admin;\nclass LoginCuserController extends Controller {\n    public function corporate() {\n        \$webALoginUrl = config('app.url_course') . '/login';\n        return redirect()->away(\$webALoginUrl);\n    }\n}\n"],
            null,
        ];
        yield 'openredirect_tp_intended_input' => [
            static fn (): AbstractAnalyzer => new OwaspOpenRedirectAnalyzer(),
            ['app/Http/Controllers/AuthController.php' => "<?php\nreturn redirect()->intended(\$request->input('next'));\n"],
            'OWASP_OPEN_REDIRECT',
        ];
        yield 'openredirect_fp_intended_literal' => [
            static fn (): AbstractAnalyzer => new OwaspOpenRedirectAnalyzer(),
            ['app/Http/Controllers/AuthController.php' => "<?php\nreturn redirect()->intended('/home');\n"],
            null,
        ];
        yield 'openredirect_tp_facade_intended_var' => [
            static fn (): AbstractAnalyzer => new OwaspOpenRedirectAnalyzer(),
            ['app/Http/Controllers/AuthController.php' => "<?php\nuse Illuminate\\Support\\Facades\\Redirect;\nreturn Redirect::intended(\$url);\n"],
            'OWASP_OPEN_REDIRECT',
        ];
        yield 'openredirect_fp_facade_intended_literal' => [
            static fn (): AbstractAnalyzer => new OwaspOpenRedirectAnalyzer(),
            ['app/Http/Controllers/AuthController.php' => "<?php\nuse Illuminate\\Support\\Facades\\Redirect;\nreturn Redirect::intended('/home');\n"],
            null,
        ];
        yield 'openredirect_tp_header_location' => [
            static fn (): AbstractAnalyzer => new OwaspOpenRedirectAnalyzer(),
            ['app/Http/Controllers/AuthController.php' => "<?php\nreturn response('', 302)->header('Location', \$request->input('next'));\n"],
            'OWASP_OPEN_REDIRECT',
        ];
        yield 'openredirect_fp_header_location_literal' => [
            static fn (): AbstractAnalyzer => new OwaspOpenRedirectAnalyzer(),
            ['app/Http/Controllers/AuthController.php' => "<?php\nreturn response('', 302)->header('Location', '/home');\n"],
            null,
        ];
        yield 'openredirect_fp_route_concat_path' => [
            static fn (): AbstractAnalyzer => new OwaspOpenRedirectAnalyzer(),
            ['app/Http/Controllers/AuthController.php' => "<?php\n\$from = \$request->input('_from', '');\nreturn redirect(route('index') . \$from);\n"],
            null,
        ];
        yield 'openredirect_fp_presigned_url' => [
            static fn (): AbstractAnalyzer => new OwaspOpenRedirectAnalyzer(),
            ['app/Services/StreamerAdapter.php' => "<?php\nreturn redirect(\$this->storage->getPresignedUrl(\$path));\n"],
            null,
        ];
        yield 'openredirect_fp_storage_temporary_url' => [
            static fn (): AbstractAnalyzer => new OwaspOpenRedirectAnalyzer(),
            ['app/Http/Controllers/AuthController.php' => "<?php\nuse Illuminate\\Support\\Facades\\Storage;\nreturn redirect()->away(Storage::disk(\$disk)->temporaryUrl(\$file, now()->addMinutes(5)));\n"],
            null,
        ];
        yield 'openredirect_fp_safe_method' => [
            static fn (): AbstractAnalyzer => new OwaspOpenRedirectAnalyzer(),
            ['app/Http/Controllers/AuthController.php' => "<?php\nreturn redirect(\$this->getSafePreviousUrl());\n"],
            null,
        ];

        // --- Path traversal ---
        yield 'traversal_tp_response_download' => [
            static fn (): AbstractAnalyzer => new OwaspPathTraversalAnalyzer(),
            ['app/Http/Controllers/DownloadController.php' => "<?php\nreturn response()->download(storage_path('docs/' . \$request->file));\n"],
            'OWASP_PATH_TRAVERSAL',
        ];
        yield 'traversal_tp_file_get_contents_var' => [
            static fn (): AbstractAnalyzer => new OwaspPathTraversalAnalyzer(),
            ['app/Services/FileService.php' => "<?php\n\$contents = file_get_contents(\$var);\n"],
            'OWASP_PATH_TRAVERSAL',
        ];
        yield 'traversal_tp_storage_get' => [
            static fn (): AbstractAnalyzer => new OwaspPathTraversalAnalyzer(),
            ['app/Services/DocService.php' => "<?php\nuse Illuminate\\Support\\Facades\\Storage;\n\$contents = Storage::get(\$name);\n"],
            'OWASP_PATH_TRAVERSAL',
        ];
        yield 'traversal_fp_basename' => [
            static fn (): AbstractAnalyzer => new OwaspPathTraversalAnalyzer(),
            ['app/Services/FileService.php' => "<?php\n\$contents = file_get_contents(storage_path('app/' . basename(\$name)));\n"],
            null,
        ];
        yield 'traversal_fp_literal' => [
            static fn (): AbstractAnalyzer => new OwaspPathTraversalAnalyzer(),
            ['app/Services/FileService.php' => "<?php\n\$contents = file_get_contents('docs/fixed.txt');\n"],
            null,
        ];
        yield 'traversal_fp_storage_path_literal' => [
            static fn (): AbstractAnalyzer => new OwaspPathTraversalAnalyzer(),
            ['app/Services/FileService.php' => "<?php\n\$contents = file_get_contents(storage_path('app/fixed.txt'));\n"],
            null,
        ];
        yield 'traversal_fp_file_var' => [
            static fn (): AbstractAnalyzer => new OwaspPathTraversalAnalyzer(),
            ['src/Analyzers/Reader.php' => "<?php\nclass Reader {\n    protected function readFile(string \$path): string {\n        return (string) file_get_contents(\$path);\n    }\n}\n"],
            null,
        ];
        yield 'traversal_tp_download_request' => [
            static fn (): AbstractAnalyzer => new OwaspPathTraversalAnalyzer(),
            ['app/Http/Controllers/DownloadController.php' => "<?php\nclass DownloadController extends Controller {\n    public function show() {\n        \$name = (string) request('file', '');\n        return response()->download(storage_path('docs/' . \$name));\n    }\n}\n"],
            'OWASP_PATH_TRAVERSAL',
        ];
        yield 'traversal_fp_output_dir_concat' => [
            static fn (): AbstractAnalyzer => new OwaspPathTraversalAnalyzer(),
            ['src/Reporters/JsonReporter.php' => "<?php\nclass JsonReporter {\n    public function render(object \$ctx): void {\n        file_put_contents(\$ctx->outputDir . '/quality-report.json', 'x');\n    }\n}\n"],
            null,
        ];
        yield 'traversal_fp_spl_pathname' => [
            static fn (): AbstractAnalyzer => new OwaspPathTraversalAnalyzer(),
            ['src/Runner/Cache.php' => "<?php\nclass Cache {\n    public function hash(object \$file): string {\n        return md5((string) file_get_contents(\$file->getPathname()));\n    }\n}\n"],
            null,
        ];
        yield 'traversal_tp_request_property' => [
            static fn (): AbstractAnalyzer => new OwaspPathTraversalAnalyzer(),
            ['app/Http/Controllers/DownloadController.php' => "<?php\nreturn response()->download(storage_path('docs/' . \$request->file));\n"],
            'OWASP_PATH_TRAVERSAL',
        ];
        yield 'traversal_fp_method_path' => [
            static fn (): AbstractAnalyzer => new OwaspPathTraversalAnalyzer(),
            ['app/Services/SmokeReportService.php' => "<?php\nclass SmokeReportService {\n    public function save(): void {\n        file_put_contents(\$this->absolutePath(), '{}');\n    }\n}\n"],
            null,
        ];
        yield 'traversal_fp_dirname_const' => [
            static fn (): AbstractAnalyzer => new OwaspPathTraversalAnalyzer(),
            ['src/Base/Config.php' => "<?php\nclass Config {\n    public function get(): object {\n        \$cfgfile = dirname(dirname(__DIR__)) . '/config/default.php';\n        return new Cfg(require \$cfgfile);\n    }\n}\n"],
            null,
        ];
        yield 'traversal_tp_file_facade' => [
            static fn (): AbstractAnalyzer => new OwaspPathTraversalAnalyzer(),
            ['app/Http/Controllers/LogController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse Illuminate\\Support\\Facades\\File;\nuse Illuminate\\Http\\Request;\nclass LogController extends Controller {\n    public function show(Request \$request) {\n        return File::get(storage_path('logs/laravel-' . \$request->date . '.log'));\n    }\n}\n"],
            'OWASP_PATH_TRAVERSAL',
        ];
        yield 'traversal_fp_nullsafe_realpath' => [
            static fn (): AbstractAnalyzer => new OwaspPathTraversalAnalyzer(),
            ['app/Uploads/ImageService.php' => "<?php\nclass ImageService {\n    public function store(\$file): string {\n        return (string) file_get_contents(\$file?->getRealPath());\n    }\n}\n"],
            null,
        ];
        yield 'traversal_fp_file_delete' => [
            static fn (): AbstractAnalyzer => new OwaspPathTraversalAnalyzer(),
            ['app/Http/Controllers/TempFileController.php' => "<?php\nnamespace App\\Http\\Controllers;\nuse Illuminate\\Support\\Facades\\File;\nclass TempFileController extends Controller {\n    public function destroy(\\Illuminate\\Http\\Request \$request): void {\n        File::delete(storage_path('tmp/' . \$request->name));\n    }\n}\n"],
            null,
        ];
        yield 'traversal_fp_tempnam_unlink' => [
            static fn (): AbstractAnalyzer => new OwaspPathTraversalAnalyzer(),
            ['app/Helpers/ExportHelper.php' => "<?php\nclass ExportHelper {\n    public function stage(string \$extension): ?string {\n        \$tmp = tempnam(sys_get_temp_dir(), 'export');\n        if (\$tmp === false) {\n            return null;\n        }\n        @unlink(\$tmp);\n        return \$tmp;\n    }\n}\n"],
            null,
        ];

        // --- Blade XSS ---
        yield 'bladexss_tp_variable' => [
            static fn (): AbstractAnalyzer => new OwaspBladeXssAnalyzer(),
            ['resources/views/comments/show.blade.php' => "<div>{!! \$comment->body !!}</div>\n"],
            'OWASP_BLADE_XSS',
        ];
        yield 'bladexss_tp_request' => [
            static fn (): AbstractAnalyzer => new OwaspBladeXssAnalyzer(),
            ['resources/views/search/show.blade.php' => "<div>{!! request('x') !!}</div>\n"],
            'OWASP_BLADE_XSS',
        ];
        yield 'bladexss_fp_csrf' => [
            static fn (): AbstractAnalyzer => new OwaspBladeXssAnalyzer(),
            ['resources/views/forms/create.blade.php' => "<form>{!! csrf_field() !!}</form>\n"],
            null,
        ];
        yield 'bladexss_fp_escaped_echo' => [
            static fn (): AbstractAnalyzer => new OwaspBladeXssAnalyzer(),
            ['resources/views/users/show.blade.php' => "<div>{{ \$name }}</div>\n"],
            null,
        ];
        yield 'bladexss_fp_manual_escape' => [
            static fn (): AbstractAnalyzer => new OwaspBladeXssAnalyzer(),
            ['resources/views/users/show.blade.php' => "<div>{!! e(\$x) !!}</div>\n"],
            null,
        ];
        yield 'bladexss_fp_rendered_html' => [
            static fn (): AbstractAnalyzer => new OwaspBladeXssAnalyzer(),
            ['resources/views/comments/comment.blade.php' => "<div>{!! \$commentHtml !!}</div>\n<div>{!! \$page->renderedHTML !!}</div>\n"],
            null,
        ];
        yield 'bladexss_fp_sanitizer' => [
            static fn (): AbstractAnalyzer => new OwaspBladeXssAnalyzer(),
            ['resources/views/frontend/lesson/detail.blade.php' => "<div>{!! sanitizeHtml(\$exercise_detail->student_content) !!}</div>\n"],
            null,
        ];
        yield 'bladexss_fp_paginator_links' => [
            static fn (): AbstractAnalyzer => new OwaspBladeXssAnalyzer(),
            ['resources/views/customer/partials/tables.blade.php' => "<div>{!! \$rows->links('pagination::bootstrap-4') !!}</div>\n"],
            null,
        ];
        yield 'bladexss_fp_event_output' => [
            static fn (): AbstractAnalyzer => new OwaspBladeXssAnalyzer(),
            ['packages/Webkul/Shop/src/Resources/views/layouts/header.blade.php' => "<div>{!! view_render_event('bagisto.shop.header.before') !!}</div>\n"],
            null,
        ];
        yield 'bladexss_fp_form_builder' => [
            static fn (): AbstractAnalyzer => new OwaspBladeXssAnalyzer(),
            ['resources/views/events/edit.blade.php' => "<div>{!! Form::model(\$event, ['route' => 'events.show']) !!}</div>\n"],
            null,
        ];
        yield 'bladexss_fp_html_builder' => [
            static fn (): AbstractAnalyzer => new OwaspBladeXssAnalyzer(),
            ['resources/views/events/index.blade.php' => "<div>{!! Html::sortable_link(trans('Name'), \$sort) !!}</div>\n"],
            null,
        ];
        yield 'bladexss_fp_json_hex' => [
            static fn (): AbstractAnalyzer => new OwaspBladeXssAnalyzer(),
            ['resources/views/pos/index.blade.php' => "<script>var C = {!! json_encode(\$cfg, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT) !!};</script>\n"],
            null,
        ];
        yield 'bladexss_tp_json_bare' => [
            static fn (): AbstractAnalyzer => new OwaspBladeXssAnalyzer(),
            ['resources/views/pos/index.blade.php' => "<script>var C = {!! json_encode(\$cfg) !!};</script>\n"],
            'OWASP_BLADE_XSS',
        ];
        yield 'bladexss_tp_dynamic_include' => [
            static fn (): AbstractAnalyzer => new OwaspBladeXssAnalyzer(),
            ['resources/views/pages/show.blade.php' => "@include(\$view)\n"],
            'OWASP_BLADE_XSS',
        ];
        yield 'bladexss_tp_dynamic_extends' => [
            static fn (): AbstractAnalyzer => new OwaspBladeXssAnalyzer(),
            ['resources/views/pages/show.blade.php' => "@extends('layouts.' . \$theme)\n"],
            'OWASP_BLADE_XSS',
        ];
        yield 'bladexss_fp_literal_include' => [
            static fn (): AbstractAnalyzer => new OwaspBladeXssAnalyzer(),
            ['resources/views/pages/show.blade.php' => "@include('partials.header')\n"],
            null,
        ];
        yield 'bladexss_fp_includewhen_literal_view' => [
            static fn (): AbstractAnalyzer => new OwaspBladeXssAnalyzer(),
            ['resources/views/pages/show.blade.php' => "@includeWhen(\$showBanner, 'partials.banner')\n"],
            null,
        ];
        yield 'bladexss_fp_number_currency' => [
            static fn (): AbstractAnalyzer => new OwaspBladeXssAnalyzer(),
            ['resources/views/orders/show.blade.php' => "<div>{!! Number::currency(\$order->total, 'USD') !!}</div>\n"],
            null,
        ];
        yield 'bladexss_fp_amount_formatter' => [
            static fn (): AbstractAnalyzer => new OwaspBladeXssAnalyzer(),
            ['resources/views/reports/budget.blade.php' => "<div>{!! format_amount_by_symbol(\$row['sum'], \$row['currency_symbol'], 2) !!}</div>\n"],
            null,
        ];
        yield 'bladexss_fp_amount_formatter_family' => [
            static fn (): AbstractAnalyzer => new OwaspBladeXssAnalyzer(),
            ['resources/views/reports/budget.blade.php' => "<div>{!! format_amount_by_currency(\$currency, \$account['max_amount']) !!}</div>\n"],
            null,
        ];
        yield 'bladexss_fp_extra_sanitizer' => [
            static fn (): AbstractAnalyzer => new OwaspBladeXssAnalyzer(['extra_sanitizers' => ['my_escape(']]),
            ['resources/views/users/show.blade.php' => "<div>{!! my_escape(\$user->bio) !!}</div>\n"],
            null,
        ];
        yield 'bladexss_tp_unknown_formatter' => [
            static fn (): AbstractAnalyzer => new OwaspBladeXssAnalyzer(['extra_sanitizers' => ['my_escape(']]),
            ['resources/views/users/show.blade.php' => "<div>{!! format_html(\$user->bio) !!}</div>\n"],
            'OWASP_BLADE_XSS',
        ];

        // --- Misconfiguration ---
        yield 'misconfig_tp_cookie_secure_false' => [
            static fn (): AbstractAnalyzer => new OwaspMisconfigurationAnalyzer(),
            ['config/session.php' => "<?php\nreturn [\n    'secure' => false,\n];\n"],
            'OWASP_MISCONFIGURATION',
        ];
        yield 'misconfig_tp_env_secure_cookie' => [
            static fn (): AbstractAnalyzer => new OwaspMisconfigurationAnalyzer(),
            ['.env' => "SESSION_SECURE_COOKIE=false\n"],
            'OWASP_MISCONFIGURATION',
        ];
        yield 'misconfig_fp_secure_cookie_true' => [
            static fn (): AbstractAnalyzer => new OwaspMisconfigurationAnalyzer(),
            ['config/session.php' => "<?php\nreturn [\n    'secure' => true,\n    'http_only' => true,\n];\n"],
            null,
        ];
    }

    /**
     * @param Closure(): (AbstractAnalyzer|InsecureHashAnalyzer|UnsafeDeserializationAnalyzer|UnsafeEvalAnalyzer|HardcodedSecretAnalyzer|MassAssignmentAnalyzer) $factory
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
        $trueNegatives = 0;
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
                } else {
                    $trueNegatives++;
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
                "\n[metrics] cases=%d TP=%d TN=%d FP=%d FN=%d precision=%.3f recall=%.3f\n",
                $truePositives + $trueNegatives + $falsePositives + $falseNegatives,
                $truePositives,
                $trueNegatives,
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
