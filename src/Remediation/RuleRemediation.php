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
 * Shape per rule: ['why' => EN one-liner, 'fix' => code sample
 * (wrong vs right), 'docs' => docs/false-positives.md anchor or null].
 */
final class RuleRemediation
{
    /**
     * @return array<string, array{why: string, fix: string, docs: ?string}>
     */
    public static function all(): array
    {
        return [
            'OWASP_BROKEN_ACCESS_CONTROL' => [
                'why' => 'A state-changing action has no authorization check, so any authenticated user (or guest) can trigger it.',
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
                'fix' => <<<'CODE'
                    // WRONG
                    eval($code);

                    // RIGHT: remove eval; use explicit allow-listed callables
                    CODE,
                'docs' => null,
            ],
            'UNSAFE_UNSERIALIZE' => [
                'why' => 'unserialize() on untrusted data enables PHP object injection.',
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
                'fix' => <<<'CODE'
                    // Delete it. Version control remembers:
                    // git log --all -- <file>  (to find it again if ever needed)
                    CODE,
                'docs' => null,
            ],
            'NAMING_CONVENTION' => [
                'why' => 'Off-convention names slow every reader and break tooling expectations.',
                'fix' => <<<'CODE'
                    // Follow PSR-12 + Laravel conventions:
                    // Classes StudlyCase, methods camelCase, constants UPPER_SNAKE
                    CODE,
                'docs' => null,
            ],
            'TODO_FIXME' => [
                'why' => 'TODO/FIXME comments are deferred work that rots into permanent debt.',
                'fix' => <<<'CODE'
                    // Either do it now, or convert to a tracked ticket and remove the comment.
                    CODE,
                'docs' => null,
            ],
            'LARAVEL_PITFALL_ENV_OUTSIDE_CONFIG' => [
                'why' => 'env() outside config/ returns null once config is cached — production-only bug.',
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
                'fix' => <<<'CODE'
                    // Delete the call; use logs or a debugger instead:
                    Log::debug('context', $data);
                    CODE,
                'docs' => null,
            ],
            'LARAVEL_PITFALL_SLEEP_IN_TEST' => [
                'why' => 'sleep() in tests makes suites slow and flaky.',
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
     * @return array{why: string, fix: string, docs: ?string}|null
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

        return $entry['why'] . "\n\n```php\n" . $entry['fix'] . "\n```";
    }
}
