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
- **False positive when**: a variable shares a name with a tainted variable but has
  been reassigned a clean value; the query builder uses binding (`where('id', $id)`) — the
  analyzer skips this case, so if it still reports, check carefully because it may be
  real taint through an intermediate variable.
- **Correct fix**: use binding/parameters instead of string concatenation:
  ```php
  DB::select('select * from users where id = ?', [$id]);
  ```

### `MASS_ASSIGNMENT`
- **True positive when**: `Model::create($request->all())` while the model has no
  `$fillable`/`$guarded`.
- **False positive when**: the model is outside the scan paths (the analyzer cannot
  resolve the model file so it stays silent — fail-open). If the project keeps models
  outside `app/`, add the scan path containing the models so this rule takes effect.
- **Correct fix**: declare `$fillable` or use a FormRequest + `validated()`.

### `OWASP_BROKEN_ACCESS_CONTROL`
- **True positive when**: a mutating action (`store`/`update`/`destroy`/...) shows no
  `authorize()`, `Gate::`, `$this->authorize()`, `abort()`, or middleware in the
  method or constructor — **and** no protective route middleware.
- **Automatically skipped when**: the action is protected by route middleware. The analyzer reads
  route files (`/routes/`, `/Routes/`, `web.php`/`api.php`) and understands:
  `Route::middleware(...)` / `->middleware(...)` chains,
  `Route::group(['middleware' => ...])` (including nested groups and groups called
  directly as statics), `Route::controller(X::class)` with the action as a bare string,
  `Route::resource()`/`apiResource()`, and `require`/`include` of route files inside
  a group closure (a required file inherits the middleware stack, it is not parsed standalone).
  Both the legacy array syntax (`['as' => ..., 'uses' => 'FQCN@method']`) and
  `[Controller::class, 'method']` are resolved.
  Middleware names containing `auth`/`can`/`permission`/`role`/`gate`/`admin`/`bouncer`/
  `checklevel`/`login`/`apikey`/`sanctum`/`jwt`/`oauth`... count as protection;
  `throttle` does not; `guest*` is never protection
  (guest means unauthenticated, even `guestAdmin` containing `admin`). Actions are matched by
  FQCN (`use` imports are resolved) so two same-named controllers in different namespaces
  (Admin vs Shop API) are not mixed up. Disable with
  `analyzers.owasp.route_middleware => false` for the legacy behavior (method-only
  checks).
- **Still reported (review then baseline)**: routes that are public by design (login,
  password reset, 2FA verify, storefront, payment callback/IPN), actions with no route
  (dead code), and sample code in documentation folders (for example the OpenAPI `Docs`
  of one pilot — example classes named `*Controller` that never run).
- **Pilot case**: HRM pilot 45 → 1 (the remaining action is 2FA verify, public by
  design); e-commerce pilot 453 → 150, of which 105 are `Docs` samples and the rest are
  public storefront/auth/callback plus a few admin methods with no route.

### `OWASP_SSRF` / `OWASP_COMMAND_INJECTION` / `OWASP_SSTI`
- The engine only reports when the URL/template/command is **not a literal** and shows
  traces of user input. If the value has passed a strict allow-list/validation, review
  then baseline instead of disabling the rule.
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
  - command injection: command strings composed entirely of deploy-time parts — literals,
    constants (`PHP_BINARY`, `DIRECTORY_SEPARATOR`), Laravel path helpers
    (`base_path()`...), `escapeshellarg()`-wrapped values, and variables assigned from
    those parts in the same function (e.g. `passthru(PHP_BINARY." $artisan ...")`
    with `$artisan = base_path('artisan')` — variables assigned from method calls
    such as `$v = $this->getVerbosity()` are still reported).
  - command injection: `new Process()` with an array command — including via an
    `array` type-hint, `@param array` docblock, or a ternary choosing between
    arrays.
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
    names (`$file`, `$path`, `$source`, `$outputDir`...) count as local
    paths — unless the root is `$request`/`request()`; dynamic
    `include`/`require` is always reported (LFI to RCE, no exemption).
  - SSTI: template variables assigned a string literal in the same function
    (`$viewName = 'backend.page'; view($viewName)`), and
    non-public helpers where every same-file call site passes a literal for the
    template parameter (public helpers are not exempted because they can be called from another file).
- **Pilot case (HRM app)**: the binary resolver uses
  `shell_exec('where ' . escapeshellarg($tool))`, `new Process($command)` with
  an array from config, and the updater uses `escapeshellarg(base_path())` —
  all 4 command injection findings resolved automatically; likewise for 9 SSRF findings
  (local files + test fixtures).

### `INSECURE_HASH`
- **True positive when**: `md5()`/`sha1()` on a password in a credential context.
- **Automatically skipped**: files mentioning `pwnedpasswords` — HIBP k-anonymity only sends
  the first 5 characters of the SHA-1 hash to the API, it does not store passwords with SHA-1.

### `MIGRATION_DESTRUCTIVE_UP`
- **True positive when**: `up()` drops a table/column that `down()` does not restore.
- **Automatically skipped**: every dropped table/column name reappears as a
  string literal in `down()` (for example a dropped column guarded by
  `Schema::hasColumn` + `down()` recreating the column).
- **Never reported**: dropping indexes/constraints (`dropIndex`, `dropUnique`,
  `dropForeign`, `dropPrimary`, `dropTimestamps`) — no data rows are lost,
  recoverable from the schema.

### `OWASP_OPEN_REDIRECT`
- **True positive when**: the target of `redirect()` / `->away()` / `->to()` /
  `Redirect::away()` is a variable, call, or concatenation containing a dynamic part.
- **Automatically skipped**: `redirect()->route()` / `Redirect::route()`, `back()`,
  string literals, `url()->previous()`, `config()`/`env()` (including concatenation where
  every leaf is safe, e.g. `redirect(config('app.url') . '/done')` — including via
  an intermediate variable `$url = config(...) . '/login'`),
  `url()` with all-literal arguments.
- **Confidence**: plain variable / `$request->input()` / dynamic concatenation = High;
  `redirect($page->getUrl())` (method/property/static — usually an internal
  URL builder) = Medium. Run `--min-confidence=high` to see only the
  most dangerous group.
- **Correct fix**: use a named route instead of an input URL:
  `redirect()->route('home')` instead of `redirect($request->input('next'))`.

### `OWASP_PATH_TRAVERSAL`
- **True positive when**: a file sink (`file_get_contents`, `Storage::get`,
  `File::get` (facade/Filesystem), `response()->download`, `include $var`, ...)
  receives a dynamic path.
- **Automatically skipped**: literals (including `storage_path()` with literal arguments),
  `basename()`-wrapped values, `env()`/`config()`, local-named variables (`$file`, `$path`,
  `$outputDir`...) except when rooted at `$request`, and `getRealPath()/getPathname()` methods.
- **No write-mode exemption**: `fopen($x, 'wb')` is still reported — writing a file to the
  wrong place is a real vulnerability (unlike read-only SSRF). Use an inline-ignore once reviewed.
- **Correct fix**: apply `basename()` to the input or pin the base directory:
  `Storage::get('docs/' . basename($name))`.

### `OWASP_BLADE_XSS`
- **True positive when**: `{!! ... !!}` contains a `$variable` or `request(` in
  `*.blade.php`.
- **Automatically skipped**: `{!! csrf_field() !!}` (no dynamic data),
  explicit sanitizers (`e()`, `sanitizeHtml()`, `strip_tags()`,
  `htmlspecialchars()`, `purify()`, `clean()`), `json_encode()` with all 4
  `JSON_HEX_*` flags (missing flags are still reported — `</script>` breakout is real),
  framework event hooks (`view_render_event(...)` — output from internal
  listeners, 440 findings from theme event hooks in one pilot), paginator `->links()`, `{{ ... }}`
  (escaped syntax), and sanitized-HTML conventions: `*Html`/`*Rendered`/`*Sanitized`
  variables or `->getHtml()`/`->renderedHTML` methods/properties
  (markdown rendered and purified at the model layer).
- **Correct fix**: switch to `{{ ... }}`; only use `{!! ... !!}` + an inline
  ignore for reviewed HTML.

### `HARDCODED_SECRET`
- The regex matches `sk-`, `AIza`, `AKIA`, private keys, ... **Test/fixture strings
  are also matched** — this is intentional. For test fixtures, either use clearly
  fake values that do not match the pattern, or exclude the test directory from the
  security scan paths.
- Placeholders such as `xxx`, `changeme`, or empty strings in config files are reported
  by `OWASP_MISCONFIGURATION` (warning level) — replace them with `env()`.

### `DISABLED_CSRF_EXCEPTION_STAR`
- **Reported as Critical when**: `$except` contains a wildcard beyond `api/*` (e.g. `*`,
  `admin/*`) — broadly disables CSRF.
- **Reported as Warning when**: only exactly `api/*` is excluded — acceptable for a stateless
  API, but verify that no session-authenticated route exists under `/api/`.

### `low` heuristic group (`DEAD_CODE`, `NAMING_CONVENTION`, `TODO_FIXME`, `MISSING_*_TEST`)
- Disabled by default (**OFF**) (`analyzers.test_coverage.*`, `analyzers.convention.*` =
  `false`). If you enable them and see a flood of warnings, that is expected —
  do not baseline them in bulk, turn them back off and only enable them for themed cleanup.

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

## 5. Don'ts

- Do not add `baseline.json` to `.gitignore` **while** complaining that CI
  reports differ per machine — an uncommitted baseline means everyone has a different threshold.
- Do not use `--fail-on=none` in CI just to keep it green — that flag is for review only.
- Do not disable `analyzers.security` / `analyzers.owasp` because of one wrong finding —
  baseline exactly that finding and keep the rule to catch new bugs.
