<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Remediation;

/**
 * Per-rule remediation catalog: what the finding means and how to fix it.
 *
 * Every entry answers the three questions every developer level needs:
 * where (already in the issue itself), WHAT (why/why_vi) and HOW (fix sample
 * plus an optional deep link into docs/false-positives.md). Reporters consume
 * this catalog so console/JSON/Markdown/HTML/SARIF all teach the fix, not
 * just the symptom.
 *
 * Shape per rule: ['why' => EN one-liner, 'why_vi' => VI one-liner,
 * 'fix' => code sample (wrong vs right), 'docs' => docs/false-positives.md
 * anchor or null].
 */
final class RuleRemediation
{
    /**
     * @return array<string, array{why: string, why_vi: string, fix: string, docs: ?string}>
     */
    public static function all(): array
    {
        return [
            'OWASP_BROKEN_ACCESS_CONTROL' => [
                'why' => 'A state-changing action has no authorization check, so any authenticated user (or guest) can trigger it.',
                'why_vi' => 'Action làm thay đổi dữ liệu nhưng không kiểm tra quyền — user nào cũng gọi được.',
                'fix' => <<<'CODE'
                    // WRONG: no authorization
                    public function destroy($id) { Order::find($id)->delete(); }

                    // RIGHT: authorize first (or protect the route with can:/auth middleware)
                    public function destroy($id) {
                        $this->authorize('delete', Order::findOrFail($id));
                        Order::find($id)->delete();
                    }
                    CODE,
                'docs' => '#owasp_broken_access_control',
            ],
            'OWASP_SSRF' => [
                'why' => 'The server fetches a URL built from user input, letting an attacker probe internal services (metadata endpoints, intranet).',
                'why_vi' => 'Server tự fetch URL ghép từ input — attacker có thể quét dịch vụ nội bộ.',
                'fix' => <<<'CODE'
                    // WRONG: arbitrary URL fetched server-side
                    $data = file_get_contents($request->input('url'));

                    // RIGHT: allow-list of hosts, or no remote fetch at all
                    $allowed = ['api.partner.com'];
                    $host = parse_url($url, PHP_URL_HOST);
                    abort_unless(in_array($host, $allowed, true), 400);
                    CODE,
                'docs' => '#owasp_ssrf--owasp_command_injection--owasp_ssti',
            ],
            'OWASP_SSTI' => [
                'why' => 'A template name from user input is rendered, letting an attacker pick which template (or template code) executes.',
                'why_vi' => 'Tên template lấy từ input rồi render — attacker có thể chọn template thực thi.',
                'fix' => <<<'CODE'
                    // WRONG: dynamic template name
                    return view($request->input('template'));

                    // RIGHT: map input through an allow-list
                    $views = ['welcome' => 'emails.welcome', 'reset' => 'emails.reset'];
                    return view($views[$request->input('template')] ?? 'emails.welcome');
                    CODE,
                'docs' => '#owasp_ssrf--owasp_command_injection--owasp_ssti',
            ],
            'OWASP_COMMAND_INJECTION' => [
                'why' => 'User input reaches an OS command, enabling remote command execution.',
                'why_vi' => 'Input lọt vào lệnh OS — attacker có thể thực thi lệnh tùy ý.',
                'fix' => <<<'CODE'
                    // WRONG: interpolated command
                    exec('convert ' . $request->input('file') . ' out.png');

                    // RIGHT: Symfony Process with argument array (no shell)
                    $process = new Process(['convert', $file, 'out.png']);
                    // or escape single arguments: escapeshellarg($file)
                    CODE,
                'docs' => '#owasp_ssrf--owasp_command_injection--owasp_ssti',
            ],
            'OWASP_XXE' => [
                'why' => 'XML parsing with external entities enabled lets attackers read local files or probe internal hosts.',
                'why_vi' => 'Parse XML mà bật external entity — attacker đọc được file local.',
                'fix' => <<<'CODE'
                    // WRONG: unguarded XML sink
                    $xml = simplexml_load_string($raw);

                    // RIGHT: forbid network + entities
                    $xml = simplexml_load_string($raw, 'SimpleXMLElement', LIBXML_NONET);
                    // or: libxml_disable_entity_loader(true); before parsing
                    CODE,
                'docs' => null,
            ],
            'OWASP_MISCONFIGURATION' => [
                'why' => 'Insecure default in config (debug on, wildcard CORS, empty secret) exposes the app in production.',
                'why_vi' => 'Config thiếu an toàn (debug bật, CORS *, secret trống) — lộ app khi lên production.',
                'fix' => <<<'CODE'
                    // WRONG (config/*.php)
                    'debug' => true, 'allowed_origins' => ['*'], 'secret' => '',

                    // RIGHT: read from environment, restrictive defaults
                    'debug' => env('APP_DEBUG', false),
                    'allowed_origins' => explode(',', env('CORS_ORIGINS', '')),
                    'secret' => env('SERVICE_SECRET'),
                    CODE,
                'docs' => null,
            ],
            'OWASP_OPEN_REDIRECT' => [
                'why' => 'Redirect target comes from user input, enabling phishing via your domain.',
                'why_vi' => 'Đích redirect lấy từ input — attacker dùng domain mình để phishing.',
                'fix' => <<<'CODE'
                    // WRONG: open redirect
                    return redirect($request->input('next'));

                    // RIGHT: named route (never a raw URL)
                    return redirect()->route('home');
                    CODE,
                'docs' => '#owasp_open_redirect',
            ],
            'OWASP_PATH_TRAVERSAL' => [
                'why' => 'A file path built from user input can escape the intended directory (../../etc/passwd).',
                'why_vi' => 'Path ghép từ input có thể thoát thư mục (../../etc/passwd).',
                'fix' => <<<'CODE'
                    // WRONG: raw user filename
                    return response()->download(storage_path('docs/' . $request->file));

                    // RIGHT: strip directories, resolve inside a fixed base
                    return response()->download(storage_path('docs/' . basename($request->file)));
                    CODE,
                'docs' => '#owasp_path_traversal',
            ],
            'OWASP_BLADE_XSS' => [
                'why' => 'Unescaped {!! !!} output of dynamic data renders attacker HTML/JS in victims’ browsers.',
                'why_vi' => '{!! !!} in dữ liệu động không escape — attacker chèn JS vào trình duyệt nạn nhân.',
                'fix' => <<<'CODE'
                    {{-- WRONG: raw output --}}
                    <div>{!! $comment->body !!}</div>

                    {{-- RIGHT: escaped echo (or e() for single values) --}}
                    <div>{{ $comment->body }}</div>
                    CODE,
                'docs' => '#owasp_blade_xss',
            ],
            'SQL_INJECTION' => [
                'why' => 'Request input concatenated into SQL lets attackers read, modify or delete any data.',
                'why_vi' => 'Nối input vào SQL — attacker đọc/sửa/xóa dữ liệu tùy ý.',
                'fix' => <<<'CODE'
                    // WRONG: string-concatenated query
                    DB::select('select * from users where id = ' . $request->input('id'));

                    // RIGHT: bound parameter
                    DB::select('select * from users where id = ?', [$request->input('id')]);
                    // or query builder: DB::table('users')->where('id', $id)->get();
                    CODE,
                'docs' => '#sql_injection--taint_sql_injection--laravel_taint',
            ],
            'TAINT_SQL_INJECTION' => [
                'why' => 'Tainted request data reaches a raw SQL sink. Same impact as SQL_INJECTION.',
                'why_vi' => 'Dữ liệu request lọt vào SQL thô — giống SQL_INJECTION.',
                'fix' => <<<'CODE'
                    // WRONG
                    DB::select(DB::raw('select * from t where a = ' . $input));

                    // RIGHT: bindings
                    DB::select('select * from t where a = ?', [$input]);
                    CODE,
                'docs' => '#sql_injection--taint_sql_injection--laravel_taint',
            ],
            'LARAVEL_TAINT' => [
                'why' => 'Request data flows into a sensitive Laravel sink (raw query, eval-like, shell).',
                'why_vi' => 'Dữ liệu request chảy vào sink nhạy cảm của Laravel.',
                'fix' => <<<'CODE'
                    // WRONG
                    Model::whereRaw('status = ' . $request->input('s'))->get();

                    // RIGHT
                    Model::where('status', $request->input('s'))->get();
                    CODE,
                'docs' => '#sql_injection--taint_sql_injection--laravel_taint',
            ],
            'TAINT_COMMAND_INJECTION' => [
                'why' => 'Tainted data reaches an OS command sink — remote command execution.',
                'why_vi' => 'Dữ liệu bẩn lọt vào lệnh OS — thực thi lệnh từ xa.',
                'fix' => <<<'CODE'
                    // WRONG
                    exec('ping ' . $host);

                    // RIGHT
                    $process = new Process(['ping', $host]); // array form, no shell
                    CODE,
                'docs' => '#owasp_ssrf--owasp_command_injection--owasp_ssti',
            ],
            'TAINT_EVAL' => [
                'why' => 'Tainted data reaches eval-like execution — arbitrary PHP execution.',
                'why_vi' => 'Dữ liệu bẩn lọt vào eval — thực thi PHP tùy ý.',
                'fix' => <<<'CODE'
                    // WRONG
                    eval('$x = ' . $input . ';');

                    // RIGHT: refactor to explicit dispatch (match, strategy map)
                    $handlers = ['a' => fn () => doA(), 'b' => fn () => doB()];
                    ($handlers[$input] ?? fn () => abort(400))();
                    CODE,
                'docs' => null,
            ],
            'TAINT_UNSAFE_SERIALIZE' => [
                'why' => 'Tainted data reaches unserialize() — PHP object injection.',
                'why_vi' => 'Dữ liệu bẩn lọt vào unserialize() — object injection.',
                'fix' => <<<'CODE'
                    // WRONG
                    $obj = unserialize($request->input('data'));

                    // RIGHT: JSON for data exchange
                    $data = json_decode($request->input('data'), true, 512, JSON_THROW_ON_ERROR);
                    CODE,
                'docs' => null,
            ],
            'UNSAFE_EVAL' => [
                'why' => 'eval()/assert()-with-string executes arbitrary PHP — almost never justifiable.',
                'why_vi' => 'eval() thực thi PHP tùy ý — gần như không bao giờ chính đáng.',
                'fix' => <<<'CODE'
                    // WRONG
                    eval($code);

                    // RIGHT: remove eval; use explicit allow-listed callables
                    CODE,
                'docs' => null,
            ],
            'UNSAFE_UNSERIALIZE' => [
                'why' => 'unserialize() on untrusted data enables PHP object injection.',
                'why_vi' => 'unserialize() dữ liệu không tin cậy — object injection.',
                'fix' => <<<'CODE'
                    // WRONG
                    $data = unserialize($cookie);

                    // RIGHT
                    $data = json_decode($cookie, true, 512, JSON_THROW_ON_ERROR);
                    CODE,
                'docs' => null,
            ],
            'HARDCODED_SECRET' => [
                'why' => 'A secret committed to source control leaks to everyone with repo access, forever (git history).',
                'why_vi' => 'Secret hardcode trong repo là lộ vĩnh viễn (cả git history).',
                'fix' => <<<'CODE'
                    // WRONG
                    'secret' => 'sk-live-abc123',

                    // RIGHT + rotate the leaked value immediately
                    'secret' => env('SERVICE_SECRET'),
                    CODE,
                'docs' => '#hardcoded_secret',
            ],
            'MASS_ASSIGNMENT' => [
                'why' => 'Model::create($request->all()) without $fillable lets attackers set protected fields (e.g. is_admin).',
                'why_vi' => 'create($request->all()) không có $fillable — attacker gán được trường cấm (vd is_admin).',
                'fix' => <<<'CODE'
                    // WRONG
                    User::create($request->all());

                    // RIGHT: declare $fillable on the model, or use validated()
                    protected $fillable = ['name', 'email'];
                    User::create($request->validated());
                    CODE,
                'docs' => '#mass_assignment',
            ],
            'INSECURE_HASH' => [
                'why' => 'md5()/sha1() are broken for passwords — brute-forced in seconds with rainbow tables/GPUs.',
                'why_vi' => 'md5()/sha1() cho password là bẻ được trong giây lát.',
                'fix' => <<<'CODE'
                    // WRONG
                    $hash = md5($password);

                    // RIGHT: adaptive hashing
                    $hash = password_hash($password, PASSWORD_ARGON2ID);
                    // verify: password_verify($password, $hash)
                    CODE,
                'docs' => '#insecure_hash',
            ],
            'DISABLED_CSRF_AUTHORIZE_TRUE' => [
                'why' => 'CSRF protection disabled — attackers can forge state-changing requests from victims’ browsers.',
                'why_vi' => 'Tắt CSRF — attacker giả mạo request đổi dữ liệu từ trình duyệt nạn nhân.',
                'fix' => <<<'CODE'
                    // WRONG: blanket exception
                    protected $except = ['*'];

                    // RIGHT: narrow, reviewed exceptions only (e.g. a signed webhook)
                    protected $except = ['stripe/webhook'];
                    CODE,
                'docs' => null,
            ],
            'DISABLED_CSRF_EXCEPTION_STAR' => [
                'why' => 'A wildcard CSRF exception disables protection for whole URL trees.',
                'why_vi' => 'Exception CSRF dạng * tắt bảo vệ cho cả cây URL.',
                'fix' => <<<'CODE'
                    // WRONG
                    protected $except = ['api/*'];

                    // RIGHT: list exact endpoints, keep the rest protected
                    protected $except = ['api/public/callback'];
                    CODE,
                'docs' => null,
            ],
            'MIGRATION_MISSING_DOWN' => [
                'why' => 'Migration without down() cannot be rolled back — a failed deploy leaves the schema half-migrated.',
                'why_vi' => 'Migration không có down() thì không rollback được khi deploy lỗi.',
                'fix' => <<<'CODE'
                    // Add the reverse operation
                    public function down(): void {
                        Schema::dropIfExists('orders');
                    }
                    CODE,
                'docs' => null,
            ],
            'MIGRATION_DESTRUCTIVE_UP' => [
                'why' => 'Dropping a table/column in up() destroys production data with no restore path.',
                'why_vi' => 'Drop table/column trong up() là mất dữ liệu production không khôi phục được.',
                'fix' => <<<'CODE'
                    // Make down() recreate what up() drops, or avoid the drop:
                    public function down(): void {
                        Schema::table('holidays', function (Blueprint $t) {
                            $t->string('country_id')->nullable();
                        });
                    }
                    CODE,
                'docs' => '#migration_destructive_up',
            ],
            'ROUTE_MISSING_VALIDATION' => [
                'why' => 'Mutating action without validation stores garbage or malicious data.',
                'why_vi' => 'Action ghi dữ liệu mà không validate — lưu rác/dữ liệu độc.',
                'fix' => <<<'CODE'
                    // WRONG
                    public function store(Request $request) {
                        return Order::create($request->all());
                    }

                    // RIGHT: FormRequest or inline validation
                    public function store(StoreOrderRequest $request) {
                        return Order::create($request->validated());
                    }
                    CODE,
                'docs' => null,
            ],
            'MISSING_CONTROLLER_TEST' => [
                'why' => 'Controller without test coverage regresses silently on every refactor.',
                'why_vi' => 'Controller không có test — refactor là vỡ mà không biết.',
                'fix' => <<<'CODE'
                    // Generate + write a feature test
                    // php artisan make:test OrderControllerTest
                    public function test_store_creates_order(): void {
                        $response = $this->post('/orders', [...]);
                        $response->assertRedirect();
                    }
                    CODE,
                'docs' => null,
            ],
            'MISSING_SERVICE_TEST' => [
                'why' => 'Business logic in services without unit tests is the most expensive code to break.',
                'why_vi' => 'Logic nghiệp vụ không test là chỗ vỡ đắt nhất.',
                'fix' => <<<'CODE'
                    // php artisan make:test --unit PricingServiceTest
                    public function test_applies_discount(): void {
                        $this->assertSame(90.0, (new PricingService())->total(100.0, 10));
                    }
                    CODE,
                'docs' => null,
            ],
            'MISSING_MODEL_TEST' => [
                'why' => 'Model scopes, casts and relations without tests hide query bugs.',
                'why_vi' => 'Scope/cast/relation của model không test sẽ giấu bug query.',
                'fix' => <<<'CODE'
                    // Add a unit test for the scope/relation, e.g. active() scope
                    public function test_active_scope_filters(): void {
                        $this->assertTrue(User::active()->whereKey($active->id)->exists());
                    }
                    CODE,
                'docs' => null,
            ],
            'MISSING_REPOSITORY_TEST' => [
                'why' => 'Repository data-access code without tests hides persistence bugs.',
                'why_vi' => 'Repository không test sẽ giấu bug persistence.',
                'fix' => <<<'CODE'
                    // Unit-test the repository method against a test database
                    public function test_finds_by_code(): void {
                        $this->assertNotNull($this->repo->findByCode('A1'));
                    }
                    CODE,
                'docs' => null,
            ],
            'MISSING_FEATURE_COVERAGE' => [
                'why' => 'A user-facing feature with no end-to-end test can break on deploy unnoticed.',
                'why_vi' => 'Feature không có test end-to-end — deploy vỡ không ai hay.',
                'fix' => <<<'CODE'
                    // php artisan make:test CheckoutFlowTest
                    public function test_checkout_flow(): void {
                        $this->post('/cart', [...])->assertOk();
                        $this->post('/checkout', [...])->assertRedirect('/done');
                    }
                    CODE,
                'docs' => null,
            ],
            'MISSING_UNIT_TEST' => [
                'why' => 'Class without unit test coverage regresses silently.',
                'why_vi' => 'Class không unit test — refactor vỡ không báo.',
                'fix' => <<<'CODE'
                    // php artisan make:test --unit FooTest
                    public function test_does_the_thing(): void {
                        $this->assertTrue((new Foo())->run());
                    }
                    CODE,
                'docs' => null,
            ],
            'TEST_WITHOUT_ASSERT' => [
                'why' => 'A test without assertions always passes — it proves nothing.',
                'why_vi' => 'Test không assert thì luôn xanh — chẳng chứng minh gì.',
                'fix' => <<<'CODE'
                    // WRONG
                    public function test_it_works(): void { (new Foo())->run(); }

                    // RIGHT
                    public function test_it_works(): void {
                        $this->assertTrue((new Foo())->run());
                    }
                    CODE,
                'docs' => null,
            ],
            'DEAD_CODE' => [
                'why' => 'Unreachable code rots: it misleads readers and still needs maintenance.',
                'why_vi' => 'Code chết gây hiểu lầm và vẫn tốn công maintain.',
                'fix' => <<<'CODE'
                    // Delete it. Version control remembers:
                    // git log --all -- <file>  (to find it again if ever needed)
                    CODE,
                'docs' => null,
            ],
            'NAMING_CONVENTION' => [
                'why' => 'Off-convention names slow every reader and break tooling expectations.',
                'why_vi' => 'Tên sai convention làm chậm người đọc và phá tooling.',
                'fix' => <<<'CODE'
                    // Follow PSR-12 + Laravel conventions:
                    // Classes StudlyCase, methods camelCase, constants UPPER_SNAKE
                    CODE,
                'docs' => null,
            ],
            'TODO_FIXME' => [
                'why' => 'TODO/FIXME comments are deferred work that rots into permanent debt.',
                'why_vi' => 'TODO/FIXME là nợ để lâu thành vĩnh viễn.',
                'fix' => <<<'CODE'
                    // Either do it now, or convert to a tracked ticket and remove the comment.
                    CODE,
                'docs' => null,
            ],
            'LARAVEL_PITFALL_ENV_OUTSIDE_CONFIG' => [
                'why' => 'env() outside config/ returns null once config is cached — production-only bug.',
                'why_vi' => 'env() ngoài config/ trả null khi config cache — bug chỉ nổ ở production.',
                'fix' => <<<'CODE'
                    // WRONG (anywhere except config/*.php)
                    $key = env('SERVICE_KEY');

                    // RIGHT
                    $key = config('services.vendor.key'); // + 'key' => env('...') in config
                    CODE,
                'docs' => null,
            ],
            'LARAVEL_PITFALL_DEBUG' => [
                'why' => 'dd()/dump() left in code kills responses (or leaks internals) in production.',
                'why_vi' => 'dd()/dump() sót lại làm chết response hoặc lộ nội bộ ở production.',
                'fix' => <<<'CODE'
                    // Delete the call; use logs or a debugger instead:
                    Log::debug('context', $data);
                    CODE,
                'docs' => null,
            ],
            'LARAVEL_PITFALL_SLEEP_IN_TEST' => [
                'why' => 'sleep() in tests makes suites slow and flaky.',
                'why_vi' => 'sleep() trong test làm suite chậm và flaky.',
                'fix' => <<<'CODE'
                    // WRONG
                    sleep(2); $this->assertQueued(Job::class);

                    // RIGHT: fake time / travel
                    $this->travel(2)->seconds();
                    CODE,
                'docs' => null,
            ],
        ];
    }

    /**
     * @return array{why: string, why_vi: string, fix: string, docs: ?string}|null
     */
    public static function for(string $rule): ?array
    {
        return self::all()[$rule] ?? null;
    }

    /**
     * Markdown help text for SARIF rule descriptors (why + fix sample).
     */
    public static function helpMarkdown(string $rule): ?string
    {
        $entry = self::for($rule);
        if ($entry === null) {
            return null;
        }

        return $entry['why'] . ' (' . $entry['why_vi'] . ")\n\n```php\n" . $entry['fix'] . "\n```";
    }
}
