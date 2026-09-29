# False Positives

The package's custom analyzers are **static heuristics**, not sound verifiers.
This guide helps you tell real findings from noise and handle them properly
instead of disabling whole rule groups.

## 1. Principles

1. **Read the finding first, decide later** — each issue has file + line + rule +
   message. Open that exact line before doing anything else.
2. **Fix code first, baseline later** — if the code can be rewritten more safely
   (parameter binding, validation, `$fillable`), fix the code.
3. **Baseline only reviewed findings** — run `--baseline-generate`/`--update`
   only after reading the full report. A blind baseline also hides real bugs.
4. **Do not broadly disable `high` confidence rules** — if there is noise, raise
   `--min-confidence` or change `--tier` instead of disabling `analyzers.security.*`.
5. **Inline ignore for reviewed one-off cases** — a
   `// quality-checker-ignore RULE` comment on the same line (or
   `// quality-checker-ignore-next-line RULE` on the line above) skips exactly
   that finding; use `all` instead of RULE to skip all rules on that line.
   Disable entirely with `analyzers.inline_suppression => false`.

## 2. Confidence & action

| Confidence | Example | Recommended action |
|---|---|---|
| `high` | `SQL_INJECTION`, `UNSAFE_EVAL`, `HARDCODED_SECRET`, `OWASP_*`, `TAINT_*`, `composer_audit` | Treat as a real bug until proven otherwise. Fix the code, do not rush to baseline. |
| `medium` | `INSECURE_HASH`, `LARAVEL_PITFALL` (`dd()`/`env()`), `MIGRATION_*`, `ROUTE_MISSING_VALIDATION` | Usually correct. Check the context (test environment? config file?) then fix or baseline. |
| `low` | `DEAD_CODE`, `NAMING_CONVENTION`, `TODO_FIXME`, `MISSING_*_TEST` | Heuristic suggestions. Enable opt-in when cleaning up code, do not gate CI on this group. |

Quick filters for review:

```bash
# Only show high-confidence findings (least noise)
php artisan quality:check --min-confidence=high --tier=security

# Standard quality CI gate (package default)
php artisan quality:check --tier=quality

# Show everything including heuristics for local cleanup
php artisan quality:check --tier=all --fail-on=none
```

## 3. Common false positives

### `SQL_INJECTION` / `TAINT_SQL_INJECTION` / `LARAVEL_TAINT`
- **True positive when**: input from the request (`$request->input()`, `$_GET`, ...) is
  concatenated or interpolated into `DB::select`, `whereRaw`, `selectRaw`, ...
- **Also covered**: column-name injection via `orderBy()`/`orderByDesc()`/`groupBy()`
  with tainted input (e.g. `orderBy($request->input('sort'))`) — the column position
  is not a bound value, so user input there is injectable.
- **False positive when**: a variable shares a name with a tainted variable but has
  been reassigned a clean value; the query builder uses binding (`where('id', $id)`) — the
  analyzer skips this case, so if it still reports, check carefully because it may be
  real taint through an intermediate variable.
- **Correct fix**: use binding/parameters instead of string concatenation:
  ```php
  DB::select('select * from users where id = ?', [$id]);
  ```
  For sort columns, map input through an allow-list:
  ```php
  $sort = in_array($request->input('sort'), ['name', 'created_at'], true) ? $request->input('sort') : 'name';
  $query->orderBy($sort);
  ```

### `MASS_ASSIGNMENT`
- **True positive when**: `Model::create($request->all())` while the model has no
  `$fillable`/`$guarded`. Also covered: `updateOrCreate()`/`firstOrCreate()`/
  `updateOrInsert()`/`firstOrNew()` with tainted data in either argument, models
  whose `$guarded = []` is explicitly empty (that guards nothing — everything stays
  mass-assignable), and `Model::unguard()` / `User::unguard()` (global unguard —
  every attribute of every model becomes fillable; the called class is resolved
  through `use` imports against the scanned model files).
- **Also covered**: `->forceFill($request->all())` — bypasses `$fillable`/`$guarded`
  by design, so it is flagged even when the model declares `$fillable`
  (seeder-style `forceFill([...literals...])` stays silent).
- **Automatically skipped**: `Model::unguard(false)` (explicit re-guard intent).
- **False positive when**: the model is outside the scan paths (the analyzer cannot
  resolve the model file so it stays silent — fail-open). If the project keeps models
  outside `app/`, add the scan path containing the models so this rule takes effect,
  and list the directory in `analyzers.models_dirs` (e.g. `app/Domain/Shop/Models`).
- **Correct fix**: declare `$fillable` or use a FormRequest + `validated()`.

### `OWASP_BROKEN_ACCESS_CONTROL`
- **Decision model**: every mutating action (`store`/`update`/`destroy`/...) gets one
  verdict per route context — `protected` / `review` / `exposed` / `unknown` — never a
  bare boolean. The finding carries the evidence: `controller`, `action`, `route`
  (methods + URI), full inherited `middleware` stack, `authorization_evidence`, and
  `semantic_status`.
- **Authentication is not authorization**: `auth`/`auth:api`/token guards (`sanctum`,
  `jwt`, API-key guards) and `verified` prove identity only. Auth-only routes yield
  `review` findings (Error severity, medium confidence — visible but non-blocking)
  instead of being suppressed. Only ability checks suppress: `can:*`, `permission:*`,
  `role:*`, configured `analyzers.extra_middleware` fragments, and local evidence
  (`$this->authorize()`, `Gate::authorize()`, enforcing `denies()` branches,
  authorizing FormRequests, `$request->authenticate()`/`Auth::attempt()` credential
  verification, `hasValidSignature()`/`hash_equals()` capability proofs).
- **Custom middleware is review, not protection**: `admin`, `owner`, `checkLevel`,
  `signed`, ... sound protective but their implementation is unknown to the engine —
  recorded as evidence for human review. (`signed`/`verified`/`throttle` are explicitly
  never authorization; `throttle`/`guest`/`web`/`api` carry no access meaning, so
  routes guarded only by them are `exposed`.)
- **Multi-route actions keep contexts separate**: one public route among protected ones
  still yields an `exposed` finding citing that route — contexts are never merged into
  "has auth". Actions with no resolvable route stay `unknown` and keep the fail-safe
  finding (Error, high confidence).
- **Automatically skipped when**: the action is protected by route middleware. Route
  contexts come from `LaravelSemanticIndex`, which reads route files (`/routes/`,
  `/Routes/`, `web.php`/`api.php`, `*ServiceProvider` loading) and understands:
  `Route::middleware(...)` / `->middleware(...)` chains, nested
  `Route::group(['middleware' => ...])` (middleware inherited through every level),
  `Route::controller(X::class)` with the action as a bare string,
  `Route::resource()`/`apiResource()` (with `only`/`except`), `Route::match()`/`any()`,
  and `require`/`include` of route files inside a group closure (a required file
  inherits the middleware stack, it is not parsed standalone).
  `base_path()`/`app_path()` targets are resolved by walking up to the project root.
  Groups nested in top-level guards (installer checks, maintenance mode) are
  descended with the ambient stack.
  Both the legacy array syntax (`['as' => ..., 'uses' => 'FQCN@method']`) and
  `[Controller::class, 'method']` are resolved. Actions are matched by
  FQCN (`use` imports are resolved) so two same-named controllers in different namespaces
  (Admin vs Shop API) are not mixed up. Disable with
  `analyzers.owasp.route_middleware => false` (no route contexts → every action is
  `unknown` and flags, the legacy method-only behavior).
- **Still reported (review then baseline)**: routes that are public by design (login,
  password reset, 2FA verify, storefront, payment callback/IPN), actions with no route
  (dead code), and sample code in documentation folders (for example the OpenAPI `Docs`
  of one pilot — example classes named `*Controller` that never run).
- **Pilot case (v0.3.2)**: Snipe-it 4 → 31 (0 suppressed, 27 new `review`: 24 behind the
  project-specific `authorize:superuser` gate middleware — human-verified as
  `Gate::allows()` authorization, clearable via `extra_middleware` or a future
  middleware-alias resolver — plus 3 pure-auth endpoints; 4 kept `exposed`/`unknown`
  unchanged). Linkstack 6 → 30 (0 suppressed, 24 new `review`: 11 behind the
  project-specific `admin` role middleware and 3 behind the ownership-checking
  `link-id` middleware — both human-verified as real authorization — plus 10
  auth-only studio/auth endpoints including genuine IDOR surface such as
  `UserController@deleteLink`; 6 kept unchanged).
- **Middleware semantic resolution (v0.3.3)**: `review` findings behind custom
  middleware are re-examined in two tiers. Tier 1 resolves the alias to a class
  (`App\Http\Kernel::$routeMiddleware` / `$middlewareAliases`,
  `bootstrap/app.php` `$middleware->alias([...])`) and locates the class file by
  `*Middleware/<Short>.php` convention — symbol resolution only. Tier 2 inspects
  `handle()` for bounded patterns: `Gate::allows()/authorize()`, `$user->can()`
  with a deny-shape (`abort*()`, `throw`, HTTP 403) on the failing path, and
  role-literal guards (`->role`/`is_admin` vs literal) passing to `$next()` with a
  deny (high confidence) or redirect (medium) fallback. A trigger only counts when
  it structurally gates `$next()` — nested inside unrelated conditions (e.g. a role
  check conjoined with a maintenance flag) it gates a branch, not the request, and
  stays review. Ownership checks (`$user->id != $link->user_id`), redirect-only
  fallbacks, truthy flags, and inverted role checks are explicitly out of scope.
  Proven middleware suppresses with composable evidence
  (`type`/`alias`/`class`/`method`/`mechanism`/`ability`/`source`/`confidence`);
  resolved-but-unrecognized middleware is attached to `review` findings as
  `middleware_resolution` so humans can clear it in seconds. `extra_middleware`
  remains the escape hatch for middleware static analysis cannot understand.
- **Pilot case (v0.3.3)**: Snipe-it 31 → 7 (24 `authorize:superuser` proven via
  `CheckPermissions::handle()` → `Gate::allows()` + 403; 3 genuine `review` kept).
  Linkstack 30 → 19 (11 `admin` proven via role guard; the 3 `link-id` ownership
  routes — including the `UserController@deleteLink` IDOR surface — correctly stay
  `review`; 0 new findings on both pilots).
- **Bounded constant propagation (v0.3.4)**: route targets, URIs, prefixes and
  include paths resolve proven-constant expressions — string literals,
  single-assignment variables (`$a = 'x'`, `$b = $a`, `$c = $a . 'y'`),
  `__DIR__`/`__FILE__`, `base_path()/app_path()/...` helpers and trivial
  `Foo::class` — through `ConstantValueResolver`, shared by the whole semantic
  engine. Conservative rules: one assignment per variable per scope (any
  conditional, repeated or later assignment → unknown), assignments must precede
  the use in the same function scope (no backward resolution, no cross-function
  leakage; enclosing registration-closure bodies contribute visibility), depth cap
  16 with cycle protection. `config()`, `env()`, `request()`, `sprintf()`, method
  calls and everything else stay unknown. Every value carries provenance
  (literal → variable → concat → use-site). The index reports coverage:
  total/resolved/full/partial/unknown plus unknown reasons (dynamic-variable,
  function-call, conditional-assignment, unsupported-expression,
  unresolved-include). Snipe-it/Linkstack BAC results are byte-identical to
  v0.3.3; Voyager stays 0 resolved with every unknown explained (37
  config-based, 6 loop-varying BREAD controllers) — `config()` support is
  deferred, and false resolution is worse than unresolved.
- **FormRequest + validation semantics (v0.3.5)**: controller parameters resolve
  to request classes through `FormRequestIndex`, exposing composable
  `ValidationEvidence` (source/fields/confidence) and `AuthorizationEvidence`
  (mechanism/ability/confidence). `rules()` presence counts even when dynamic —
  but then fields are unknown (medium confidence, never false-safe); a resolved
  FormRequest *without* `rules()` is no validation evidence. `authorize()`
  returning literal `true` (or absent) is explicitly not authorization;
  `can`/`Gate`/deny/403 patterns are strong evidence, other non-trivial bodies
  stay protective (medium). Inline `$request->validate([...])`,
  `Validator::make(...)` and `validated()`/`safe()` are recognized separately
  (validated-*use* is the bridge later mass-assignment work needs). Unresolvable
  `*Request` hints keep the legacy name-heuristic suppression (low confidence).
  BAC consumes the same evidence with unchanged outcomes; Voyager config()
  unknowns are kept as the future config-semantics benchmark.
- **Policy / Gate semantic mapping (v0.3.6)**: `PolicyRegistry` resolves
  model → policy (`AuthServiceProvider::$policies`, `Gate::policy()`) and
  ability → `Gate::define()` (trivial `fn () => true` defines are not
  evidence, mirroring the `authorize() => true` rule). Convention alone
  (`Post` → `PostPolicy`) never maps — unregistered chains stay
  medium/unresolved, never guesses. `ModelTypeResolver` recovers subject
  types from parameter hints, single straight-line `Model::...`/`new Model`
  assignments and one variable hop; properties and dynamic expressions stay
  unknown. `resolveAuthorizeCall(ability, model)` returns the full chain
  (model → policy → method, high) when proven, ability-only (medium) for
  defined abilities without a model, unresolved (medium) otherwise. Policy
  methods only need to exist — the framework enforces their boolean, so no
  body analysis is required (unlike middleware gates). Self-enforcing calls
  (`$this->authorize()`, `Gate::authorize()`) fail closed at runtime and
  therefore never flag, even with unresolved chains; bare `Gate::allows()`
  without an enforcing branch still flags (polarity preserved).   BAC outcomes
  are byte-identical on both pilots (7/7, 19/19); `authorizeResource()`
  per-action mapping stays a sub-wave.
- **Input-to-Eloquent flow classification, shadow mode (v0.4.1)**: the first
  joint data-flow + framework-semantics analyzer. `MassAssignmentFlow`
  classifies each mass-assignment sink argument by provenance — raw request
  (`all()`/`input()`), validated (`validated()`/`safe()`/`validate()`),
  bounded (`only([...])`, `safe()->only([...])`), internal (literal arrays),
  unknown (service returns, conditional raw/safe mixes, dynamic keys) — with
  `except()` exclusions recorded and `forceFill`/`forceCreate` distinguished
  as guard-bypassing sinks. Variable propagation reuses the shared engine
  (`AssignmentMap::visible` + same-scope filtering + single-assignment
  discipline). `validated` never implies mass-assignment safe. Findings carry
  the classification as `flow_provenance` metadata (source → propagation →
  sink trace) without changing any decision; the legacy analyzer is untouched
  otherwise. Snipe-it probe: 194 sinks classified (98 internal, 51 unknown,
  38 raw, 4 validated, 2 bounded) against 1 legacy finding (`unguard()` —
  no data flow by design); linkstack 28 sinks, all internal. The 38 raw
  instance-`fill()` flows the legacy analyzer cannot see are the v0.4.2
  escalation pool, once `$fillable`/`$guarded` field-set reasoning lands.
- **Production decision integration (v0.4.3)**: the analyzer runs
  decision-first with deliberate fallback — SAFE suppresses (only when
  provenance, target, assignability are all known, no bypass, no global
  unguard), EXPOSED emits Error/High, REVIEW emits Warning/Medium with the
  full chain payload (`verdict`/`input_kind`/`source`/`sink`/
  `model_protection`/`bypass`/`confidence`/`flow`), UNKNOWN and
  no-context sinks keep the byte-identical legacy heuristic. Framework
  default-guarded models (neither property declared) suppress with
  evidence; partially-guarded models with raw input become REVIEW instead
  of silent. Findings answer the whole chain
  (`$request->all()` → `$data` → `$user->fill($data)` → model → guarded
  → decision). Snipe-it 1 → 3 (gone 0; 2 new REVIEW both human-verified:
  `CustomFieldsetsController@store/update` fill raw input into a
  `guarded = ['id']`-only model — authorized but all-but-`id` assignable);
  linkstack 0 → 0. Protocol from here on: every new EXPOSED/REVIEW and
  every gone finding gets 100% human review before the semantic engine
  earns production-outcome power.
- **Model metadata + assignability decisions, shadow mode (v0.4.2)**:
  `ModelMetadata` returns state, never bare arrays — `fillable` non-empty
  wins (FILLABLE), `$guarded = []` guards nothing (UNGUARDED), `['*']` or
  neither property declared (framework default) guards everything
  (GUARDED), explicit lists stay lists, dynamic values are UNKNOWN (never
  empty). A non-seed `Model::unguard()` without `reguard()` marks every
  model unguarded; scoped `unguarded()` does not. `MassAssignmentDecision`
  reasons Source × Model: raw into unguarded → EXPOSED; validated/bounded
  into unguarded → REVIEW (validated is never auto-safe); `force*`
  bypasses model protection (raw → EXPOSED, else REVIEW); fillable and
  guarded-all models → SAFE; guarded-list → REVIEW unless bounded input is
  fully guarded; internal data → SAFE; unknown model/input → UNKNOWN.
  Instance targets resolve via params, single straight-line
  `Model::...`/`new Model` assigns (later reassignments do not poison
  earlier uses) and one variable hop. The analyzer is untouched — shadow
  only. Snipe-it 38 raw flows: 34 SAFE via `$fillable` (sampled),
  2 REVIEW via `$guarded = ['id']` (CustomFieldset), 2 UNKNOWN via
  loop-nested assigns; 0 EXPOSED, and no `$guarded = []` exists in its
  models, so zero is correct rather than a miss. Full-pilot verdicts:
  snipe-it 138 safe / 2 review / 53 unknown, linkstack 28 safe.

### `OWASP_SSRF` / `OWASP_COMMAND_INJECTION` / `OWASP_SSTI`
- The engine only reports when the URL/template/command is **not a literal** and shows
  traces of user input. If the value has passed a strict allow-list/validation, review
  then baseline instead of disabling the rule.
- Backtick shell execution (`` `...` ``) with any dynamic part is always reported
  as command injection — there is no escaping mechanism for backticks, so no exemption applies.
- **Automatically skipped**:
  - sinks in test paths (`tests/`, `Test.php`) — applies to SSRF,
    command injection, XXE;
  - `fopen()` in write/append mode (`w`, `a`, `x`, `c`, ...) — creates a local file,
    not a server-side request;
  - arguments shaped as a local path: a variable/property name suggesting a file
    (`$path`, `$file`, `$source`, `$fullPath`, ...) with no remote hint
    (`$url`, `$endpoint`, ...), or built from `storage_path()`/`base_path()`/
    `public_path()`/...
  - command injection: arguments already wrapped with `escapeshellarg()`/`escapeshellcmd()`,
    and `new Process()` with an array command (no shell — even when
    the array is in a `$command = [...]` variable in the same function).
  - command injection: `pcntl_exec()`, backtick execution with any dynamic part,
    and `Process::fromShellCommandline()` with user input are always reported —
    backticks have no escaping mechanism and shell-commandline strings always
    go through a shell.
  - command injection: command strings composed entirely of deploy-time parts — literals,
    constants (`PHP_BINARY`, `DIRECTORY_SEPARATOR`), Laravel path helpers
    (`base_path()`...), `escapeshellarg()`-wrapped values, and variables assigned from
    those parts in the same function (e.g. `passthru(PHP_BINARY." $artisan ...")`
    with `$artisan = base_path('artisan')` — variables assigned from method calls
    such as `$v = $this->getVerbosity()` are still reported).
  - command injection: `new Process()` with an array command — including via an
    `array` type-hint, `@param array` docblock, or a ternary choosing between
    arrays.
  - command injection: `mail()` is only reported when the 5th argument
    (`$additional_parameters`, passed to sendmail as CLI flags) is present —
    recipient/subject/body/headers alone cannot inject shell flags.
  - command injection: parameters of non-public functions where every same-file call
    site passes a literal/deploy-time-safe value (a private helper only called with literals).
  - command injection: `foreach` loop variables over an array literal or class constant
    (`foreach (self::LIST as $item)` — deploy-time values).
  - SSRF: `new GuzzleHttp\Client([...])` is not a sink (the constructor only takes
    a config array — the real request at `->get()`/`->post()` is covered
    separately); for Guzzle `$client->request($method, $url)` the URL is the 2nd argument;
    `->getRealPath()`/`->getPathname()` (UploadedFile/SplFileInfo)
    are always local paths; fixed-literal-host URLs
    (`sprintf('https://example.com/...', $v)`, including via intermediate variables)
    are not SSRF; `env()`/`config()` are deploy-time,
    even when wrapped in `rtrim()`/`sprintf()`/all-deploy-time concatenation.
  - SSRF/traversal share a naming convention: variables/properties with local-suggesting
    names (`$file`, `$path`, `$source`, `$outputDir`, `$tmp`, `$dest`...) count as local
    paths — unless the root is `$request`/`request()`; `?->` nullsafe chains
    follow the same rules; `$this->prop` assigned only deploy-time values
    (SSRF: `env()` in constructor) counts as deploy-time; `copy()`/`readfile()`/
    `file()` count as read sinks;
    `fsockopen()`/`pfsockopen()`/`stream_socket_client()` read the host from
    the first argument (literals like `'localhost'` stay silent);
    `curl_setopt($ch, CURLOPT_URL, $url)` reads the URL from the third argument;
    dynamic `include`/`require` is always reported (LFI to RCE, no exemption).
  - XXE: `LIBXML_NOENT` is not protection — it substitutes entities (enables
    XXE). Only `LIBXML_NONET` / `libxml_disable_entity_loader(true)` silence
    a file.
  - SSRF: directory listings are server-side paths, never remote URLs —
    `glob()`/`scandir()`/`readdir()` (including via `foreach` loop variables and
    `$list[$i]` element reads: `foreach (glob(...) as $f)`,
    `$uploads['k'] = glob(...)`), `Storage::files()`/`allFiles()`,
    `File::files()`. Deploy-time path builders count too: `dirname()`/
    `basename()`/`realpath()` over deploy-time values, `__DIR__`/`__FILE__`.
    URLs gated by a `*sanitiz*()` call in the same function stay silent
    (`if (!sanitizeRemoteUrl($url)) throw ...;`).
  - SSTI: template variables assigned a string literal — or a concatenation
    composed solely of literals, numbers, class constants and known variables
    (`$viewName = 'front.pos_' . $industry`, `Blade::render('...' . Color::Gray[400])`),
    template registry properties (`$this->views['show']`, `$this->template`),
    non-public helpers where every same-file call site passes a literal for the
    template parameter (public helpers are not exempted because they can be called from another file),
    and variables gated by an `in_array()` allow-list of literals in the same
    function (`if (in_array($type, ['a', 'b'])) { view("x.{$type}"); }` — the
    list may be inline or a variable assigned only literal arrays; a dynamic
    list variable stays flaggable).
  - SSTI sinks include `View::make()/composer()/creator()` in addition to
    `view()`/`Blade::render()`; named `url:`/`uri:`/`path:` arguments are read
    as the SSRF target instead of the first positional argument.
  - XXE sinks include `XMLReader::open($uri)` / `$reader->open($uri)` in
    addition to `simplexml_load_*` / `DOMDocument::load*` / `new SimpleXMLElement`.
- **Pilot case (HRM app)**: the binary resolver uses
  `shell_exec('where ' . escapeshellarg($tool))`, `new Process($command)` with
  an array from config, and the updater uses `escapeshellarg(base_path())` —
  all 4 command injection findings resolved automatically; likewise for 9 SSRF findings
  (local files + test fixtures).

### `INSECURE_HASH`
- **True positive when**: `md5()`/`sha1()` — or `hash('md5'|'sha1'|'md4', ...)` —
  on a password in a credential context.
- **Also covered**: `rand()`/`mt_rand()`/`uniqid()` assigned to a token/secret
  variable (`$otp`, `$resetToken`, `['verification_code' => ...]`, returned from
  a `generate*Token()` function) — predictable RNG for security tokens; use
  `random_int()`/`random_bytes()`. Counters, offsets and filenames stay silent,
  and `random_int()`/`random_bytes()` never flag.
- **Automatically skipped**: files mentioning `pwnedpasswords` — HIBP k-anonymity only sends
  the first 5 characters of the SHA-1 hash to the API, it does not store passwords with SHA-1.

### `INSECURE_COOKIE`
- **Reported when**: `Cookie::queue()/make()/forever()`, the `cookie()` helper,
  or `->cookie()` on a response omits the `$secure` flag (Warning — relies on
  `session.secure_cookie`, verify it) or passes literal `false` (Error).
  Literal `true` or a config-driven expression stays silent.

### `SESSION_FIXATION`
- **Reported when**: a login call (`Auth::attempt()`, `->login()`/
  `->loginUsingId()`) has no session rotation in the same function. Either
  `session()->regenerate()` or `regenerateToken()` counts.

### `WEAK_PASSWORD_POLICY`
- **Reported when**: `Password::min(N)` with N < 8, a `password` validation rule
  with `min:N` below 8, or a `password` rule with no length floor at all
  (including `$rules` variables returned from `rules()`).
- **Not inspected**: the custom-messages argument (`'password.min' => '...'`
  names a message, not a field), non-password fields, `min:8+`, and rule
  objects such as `Password::min(8)`.

### `ROUTE_MISSING_VALIDATION`
- **Reported when**: a mutating controller action (`store`/`update`/`delete`/...)
  shows no `$request->validate()`/`validated()`/`Validator::make()` call and no
  FormRequest parameter.
- **Automatically skipped**: FormRequest type-hints resolved through `use`
  imports (`store(StoreRequest $request)` with
  `use App\Http\Requests\StoreRequest;` — the short name alone used to miss).

### `MIGRATION_DESTRUCTIVE_UP`
- **True positive when**: `up()` drops a table/column that `down()` does not restore —
  including raw `DROP TABLE/DATABASE`, `TRUNCATE`, and `ALTER TABLE ... DROP COLUMN`
  via `DB::statement()`/`DB::unprepared()`.
- **Automatically skipped**: every dropped table/column name reappears as a
  string literal in `down()` (for example a dropped column guarded by
  `Schema::hasColumn` + `down()` recreating the column).
- **Never reported**: dropping indexes/constraints (`dropIndex`, `dropUnique`,
  `dropForeign`, `dropPrimary`, `dropTimestamps`) — no data rows are lost,
  recoverable from the schema.

### `OWASP_OPEN_REDIRECT`
- **True positive when**: the target of `redirect()` / `->away()` / `->to()` /
  `->intended()` / `Redirect::away()` / `Redirect::intended()` /
  `response(...)->header('Location', ...)` is a variable, call, or concatenation
  containing a dynamic part.
- **Data-flow v0.1**: only straight-line assignments in the same function,
  above the sink, count — a literal assigned later or in another function
  never silences. `str_starts_with()` prefix gates with reassignment
  (`if (!str_starts_with($v, $safe)) { $v = '/'; }`), early enforcement
  (`throw`/`abort`/`return`), and guarded ternaries count; suffix/contains
  checks do not. Shared primitives (`ScopeResolver`, `AssignmentMap`,
  `GuardMap`) back SSRF and traversal too, and findings carry a `flow`
  trace (source → propagation → sink) in metadata.
- **Automatically skipped**: `redirect()->route()` / `Redirect::route()`, `back()`,
  string literals, `url()->previous()`, `config()`/`env()` (including concatenation where
  every leaf is safe, e.g. `redirect(config('app.url') . '/done')` — including via
  an intermediate variable `$url = config(...) . '/login'`),
  `url()` with all-literal arguments, concatenations led by a host-pinning call
  (`redirect(route('index') . $from)` — the framework host cannot change, only the
  path varies; note `url($dynamic)` is NOT safe because `url()` returns
  already-valid URLs unchanged), `sprintf()` with a fixed-host format
  (`sprintf('https://oauth.host/authorize?%s', $query)` — including via a
  variable assigned that literal), no-argument `$request->url()` concatenations
  (current-URL getter), SDK-signed storage URLs
  (`Storage::disk()->temporaryUrl()`, `->getPresignedUrl()`) and OAuth SDK
  authorization URLs (`->getAuthorizationUrl()` — the host is the configured
  provider), and `*Safe*` methods (`getSafeUrl()`,
  `getSafePreviousUrl()` — same naming-convention trade-off as `*Html`).
- **Confidence**: plain variable / `$request->input()` / dynamic concatenation = High;
  `redirect($page->getUrl())` (method/property/static — usually an internal
  URL builder) = Medium. Run `--min-confidence=high` to see only the
  most dangerous group.
- **Correct fix**: use a named route instead of an input URL:
  `redirect()->route('home')` instead of `redirect($request->input('next'))`.

### `OWASP_PATH_TRAVERSAL`
- **True positive when**: a file sink (`file_get_contents`, `Storage::get`/`putFile`,
  `File::get` (facade/Filesystem), `unlink`/`rename`, `response()->download`,
  `include $var`, ...) receives a dynamic path.
- **Automatically skipped**: literals (including `storage_path()` with literal arguments),
  `basename()`-wrapped values, `env()`/`config()`, local-named variables (`$file`, `$path`,
  `$outputDir`...) except when rooted at `$request`, `getRealPath()/getPathname()` methods,
  `File::`/`Storage::delete()` (deleting a file cannot exfiltrate or include its contents),
  and paths from `tempnam()`/`tmpfile()`/`sys_get_temp_dir()` (fresh server-side temp files).
- **No write-mode exemption**: `fopen($x, 'wb')` is still reported — writing a file to the
  wrong place is a real vulnerability (unlike read-only SSRF). Use an inline-ignore once reviewed.
- **Correct fix**: apply `basename()` to the input or pin the base directory:
  `Storage::get('docs/' . basename($name))`.

### `OWASP_BLADE_XSS`
- **True positive when**: `{!! ... !!}` contains a `$variable` or `request(` in
  `*.blade.php` — or a view directive (`@include`/`@extends`/`@includeWhen`/
  `@includeFirst`/`@each`) takes a dynamic view name (`@include($view)`,
  `@extends('layouts.' . $theme)`). A steerable template name loads and
  executes unintended PHP, so it is reported with Medium confidence (Blade has
  no data-flow analysis — string literals and `config()`/`env()` stay silent).
- **Severity split**: request-derived output (`request(...)`, `$request`,
  `$_GET`/`$_POST`) is Error/High; other dynamic output is Warning/Medium —
  it may be pre-sanitized or intentionally trusted HTML.
- **Automatically skipped**: `{!! csrf_field() !!}` (no dynamic data),
  explicit sanitizers (`e()`, `sanitizeHtml()`, `strip_tags()`,
  `htmlspecialchars()`, `purify()`, `clean()`, `md_to_html()`,
  `markdownHelp()`/`markdownNotes()` (HTMLPurifier), `excerpt()` (tag-stripped
  summary convention), plus project-specific functions
  listed in `analyzers.extra_sanitizers`), ternaries with all-literal branches
  (`{!! $checked ? 'checked' : '' !!}` — only branches render; Elvis `$x ?: 'd'`
  still flags because it renders `$x`), `json_encode()` with all 4
  `JSON_HEX_*` flags (missing flags are still reported — `</script>` breakout is real),
  framework event hooks (`view_render_event(...)` — output from internal
  listeners), form builders (`Form::`/`Html::` — values escaped by the
  builder), paginator `->links()` / `->appends()->render()`, `{{ ... }}`
  (escaped syntax), numeric formatters (`Number::currency()`/`format()`/...,
  `format_amount_by_symbol()`/`_code`/`_currency`/`_account` — NumberFormatter
  float-cast output cannot carry markup), and sanitized-HTML conventions: `*Html`/`*Rendered`/`*Sanitized`
  variables or `->getHtml()`/`->renderedHTML` methods/properties
  (markdown rendered and purified at the model layer).
- **Correct fix**: switch to `{{ ... }}`; only use `{!! ... !!}` + an inline
  ignore for reviewed HTML.

### `HARDCODED_SECRET`
- The regex matches `sk-`, `AIza`, `AKIA`, private keys, ... **Obvious fixtures
  in test paths are skipped** (`whsec_test_secret`, `AKIA...EXAMPLE` — matched
  values containing test/fake/example/sample/demo/mock/dummy/changeme/
  placeholder/xxx). Production values with those markers still flag. For other
  test fixtures, either use clearly fake values, or exclude the test directory
  from the security scan paths.
- **Identifier constants are skipped**: `FEATURE_X = 'x_value'` /
  `PASSWORD_FIELD = 'password'` / `define('ROUTE', 'route.name')` where the
  UPPER_SNAKE name and the slug value name each other (either normalized form
  contains the other). Real secrets in constants (`API_KEY = 'sk-live-...'`,
  `DEFAULT_PASSWORD = 'admin123'`) still flag — as do variable assignments.
- **Password comparisons** (`$credentials['password'] == 'long-literal'`) are
  reported as master-password pattern — including Yoda order. Variable-to-variable
  comparisons stay silent.
- Every finding carries `evidence`: matched prefix (first 32 chars), length,
  Shannon entropy, known token prefix (`sk_live_`, `ghp_`, ...) or null, and
  whether it looks like a test fixture.
- Field-name constants (e.g. `OPT_DB_PASSWORD = 'db-password'`) are skipped —
  the right side names a CLI option, it is not a credential.
- Placeholders such as `xxx`, `changeme`, or empty strings in config files are reported
  by `OWASP_MISCONFIGURATION` (warning level) — replace them with `env()`.

### `OWASP_MISCONFIGURATION`
- **Reported when**: debug mode is on (`'debug' => true`, `APP_DEBUG=true`),
  CORS allows wildcard origins, a placeholder/empty secret is present, or session
  cookies weaken their flags (`'secure' => false`, `'http_only' => false`,
  `SESSION_SECURE_COOKIE=false`, `same_site => 'none'`).
- Only real config files are scanned (`/config/`, `.env`), never tests/seeders.

### `UNSAFE_EVAL`
- **Reported when**: `eval()`/`assert()`/`create_function()`/`call_user_func()`/
  `call_user_func_array()` receive a non-literal first argument. Only the callable
  position is checked — tainted *arguments* to a literal callable are the callee's business.
- **Automatically skipped**: literals, fixed callables (`[$this, 'handle']`,
  `$this->callback` properties holding internally-assigned handlers,
  `app('router')`/`resolve(...)` container lookups with all-literal arguments),
  `assert()` with provably-boolean arguments (`instanceof`, comparisons,
  `empty()`/`isset()`, `is_*()` predicates), and expressions
  whose every dynamic leaf was validated by `preg_match()`/`preg_match_all()` in the
  same function (e.g. a math expression allow-listed before eval). Filter strength itself is
  not verified — review the regex.

### `UNSAFE_UNSERIALIZE`
- **Reported when**: `unserialize()` / `yaml_parse()` / `yaml_parse_file()` /
  `yaml_parse_url()` receive a non-literal argument (YAML tags can instantiate
  PHP objects). Literals (including class constants) are skipped.
- **Automatically skipped**: `unserialize($data, ['allowed_classes' => false])` —
  with object instantiation disabled the object-injection vector is closed.

### `DISABLED_CSRF_EXCEPTION_STAR`
- **Reported as Critical when**: `$except` contains a wildcard beyond `api/*` (e.g. `*`,
  `admin/*`) — broadly disables CSRF.
- **Reported as Warning when**: only exactly `api/*` is excluded — acceptable for a stateless
  API, but verify that no session-authenticated route exists under `/api/`.

### `low` heuristic group (`DEAD_CODE`, `NAMING_CONVENTION`, `TODO_FIXME`, `MISSING_*_TEST`)
- Disabled by default (**OFF**) (`analyzers.test_coverage.*`, `analyzers.convention.*` =
  `false`). If you enable them and see a flood of warnings, that is expected —
  do not baseline them in bulk, turn them back off and only enable them for themed cleanup.
- `MISSING_*_TEST` means "no directly associated test detected", not "untested":
  the class may be covered by feature/API/E2E suites under unrelated names.
  They report at Info/Low for exactly this reason — wire real coverage data
  instead of gating on filenames.

## CI gate & exit codes

- Exit codes: `0` = gate passed, `1` = quality gate failed, `2` = checker or
  internal error (e.g. context build failure). Safe for GitHub Actions, GitLab
  CI, Jenkins, pre-commit and pre-push hooks.
- `quality_gate.ignore` (config) and `--ignore=` (CLI, comma-separated) hide
  rules from reports and the gate, e.g. `MISSING_MODEL_TEST` noise on legacy
  projects. `--fail-on=` sets the severity threshold, `--min-confidence=`
  drops low-confidence findings from the gate.

## Delta vs baseline & confidence scores

- With a `baseline.json` present, every run prints `Delta vs baseline: X new,
  Y fixed, Z existing` (console), plus a `delta` block in JSON and a Delta
  card in HTML. Moved lines count as new+fixed (same trade-off as baselining).
- Every finding carries a numeric `confidence_score` (High 1.0 / Medium 0.5 /
  Low 0.25), shown in JSON and next to the confidence badge in HTML. The
  Quality Score dashboard deducts severity x confidence per finding, so
  low-confidence noise cannot nuke the score — and only high-confidence
  severe findings block the release gate.

## 4. Suggested review flow

```bash
# 1. See the full picture without failing
php artisan quality:check --format=all --fail-on=none

# 2. Focus on high-confidence findings first
php artisan quality:check --min-confidence=high --tier=security --fail-on=none

# 3. Fix what can be fixed in code (binding, fillable, validation, authorize)

# 4. Accept the reviewed remainder as baseline
php artisan quality:check --baseline-generate

# 5. From now on CI only fails on NEW findings
php artisan quality:check --ci --baseline-file=baseline.json
```

Commit `baseline.json` so the whole team shares the same threshold. Only run
`--baseline-update` after re-reviewing the full new report.

## 6. Performance budget (semantic engine)

Optimization stays P2 — no caching layers before profiling. Budgets (Snipe-it,
713 files, measured):

| Stage | Warm | Notes |
|---|---|---|
| Semantic index build | ~0.2s | 26 route/provider files, AstPool 25 hits / 26 misses |
| BAC analyze (incl. registry + handle inspection) | ~3.0s | per-file parse dominates; middleware inspection parses one file per distinct alias |
| Cold full BAC scan | < 30s | first-touch outlier 28.7s (file cache + autoload); warm ~3–4s |

Rules going forward:

- Index build once per run; AST parse once per file per run (AstPool).
- Middleware inspection parses at most one file per distinct alias, memoized.
- If a wave pushes the cold full scan past ~50s, stop features and optimize
  (shared parser/AstPool across analyzers is the known lever: raw re-parse of
  ~7k files costs ~110s today because every analyzer constructs its own
  `ParserFactory` per file).
- No complex caching before a profile proves where time goes.

## 5. Don'ts

- Do not add `baseline.json` to `.gitignore` **while** complaining that CI
  reports differ per machine — an uncommitted baseline means everyone has a different threshold.
- Do not use `--fail-on=none` in CI just to keep it green — that flag is for review only.
- Do not disable `analyzers.security` / `analyzers.owasp` because of one wrong finding —
  baseline exactly that finding and keep the rule to catch new bugs.
