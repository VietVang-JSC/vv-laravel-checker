# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added (standalone scan)
- `bin/quality-check`: scan any directory without installing the package
  into the target (no target vendor/artisan needed). Same engine, formats,
  baseline/delta and exit codes as `php artisan quality:check`; defaults
  to `--only=custom`.

## [0.7.0] - 2026-10-01

### Added (report actionability, all 5 formats)
- Action priority P0-P3 on every finding (HTML, JSON, Markdown, console,
  SARIF): deterministic projection of severity x confidence x dimension,
  with an auditable mapping table in the report (no magic scores).
- Risk Overview split (HTML, Markdown, JSON): per-category findings,
  highest severity and scheduling action — Security vs Testability vs
  Database vs the rest, so totals never read as pure vulnerabilities.
- Quality Score card shows `Overall/100` with the release gate badge plus
  an explicit `Release Blockers` count.
- Remediation entries for `OWASP_OWNERSHIP_IDOR` and
  `OWASP_BLADE_DYNAMIC_INCLUDE`.

### Changed
- New rule `OWASP_BLADE_DYNAMIC_INCLUDE` split out of `OWASP_BLADE_XSS`:
  dynamic view names (`@include($view)`) are an LFI vector, not script
  injection. Baselines referencing the old rule id should be regenerated.
- Laravel 9 support: `illuminate/console` + `illuminate/support`
  `^9.0|^10.0|^11.0|^12.0` (verified with a real Laravel 9 install).

### Validation
- `878` tests and `2,222` assertions pass, metrics precision `1.000`.
- Proven end-to-end via `composer require` + `php artisan quality:check`
  on a real Laravel 9 project (203 findings, P0 36 / P1 122 / P3 45).

## [0.6.2] - 2026-10-01

### Added (Ownership / Object-Level Authorization)
- Production mapping for conservative Ownership/IDOR decisions:
  `PROTECTED` stays silent, strong `REVIEW` and `EXPOSED` decisions become
  findings, and `UNKNOWN` does not become a false positive.
- BAC reconciliation merges matching ownership evidence into existing BAC
  findings and preserves the complete ownership provenance chain.
- Duplicate BAC/ownership findings are suppressed by controller/action
  identity; standalone ownership findings remain when BAC has no counterpart.
- Injected repository/service dependencies are not treated as
  route-controlled resource identifiers.

### Validation
- `874` tests and `2,163` assertions pass.
- Four-pilot production evaluation: Linkstack, Snipe-it, Firefly-III and
  Canvas; all `11/11` new findings were human-reviewed as useful review,
  with `0` confirmed false positives and `0` duplicates.
- Protected mechanisms remained silent, including policy/gate, explicit
  owner-compare deny, relationship-scoped and owner-where corpus coverage.
- Parse amplification remained `1.0x`; ownership analyzer wall time was
  approximately `3.2-3.7s` on the evaluation box.
- Performance is accepted with benchmark variance. Paired full-engine runs
  were environment-noisy (`+18.22s`, `-13.96s`, `+4.29s`); memory remained
  effectively unchanged (`1268MB` off vs `1270MB` on). A quiet-box rerun is
  post-release verification, not a correctness blocker.

## [Unreleased]

### Added (analysis engine foundation)
- `src/Analysis/AstPool.php`: parse-once-per-run shared AST pool plus
  `AstPoolAware` opt-in (wired in `CustomAnalyzerChecker`); legacy analyzers
  keep parsing on their own.
- Open redirect migrated to data-flow v0.1: scope- and line-ordered variable
  maps plus `str_starts_with()` sanitizer-gate recognition (reassign, early
  enforcement, guarded ternary).
- Per-rule precision/recall/F1 table in the metrics test output.
- Shared flow primitives (`ScopeResolver`, `AssignmentMap`, `GuardMap`,
  `FlowTrace`): SSRF, traversal and redirect now propagate through one
  engine; redirect findings carry a `flow` trace in metadata.

### Added (expert-review wave 2)
- Delta vs baseline: console line, JSON `delta` block and HTML Delta card
  (New / Fixed / Existing) whenever a `baseline.json` is present.
- Numeric `confidence_score` per finding (High 1.0 / Medium 0.5 / Low 0.25)
  in JSON payloads and next to HTML confidence badges; quality-score
  deductions use the same weights.

### Changed (rebrand)
- Renamed package `vietvang/quality-checker` → `rampart/laravel-checker` and
  namespace `VietVang\QualityChecker` → `Rampart\QualityChecker` (all sources,
  tests, docs, SARIF links). Locked LF line endings via `.gitattributes`.

### Changed (source hygiene)
- PHPStan 1.12 (EOL) → 2.0; `treatPhpDocTypesAsCertain: false` (finder
  generics already narrow node types — defensive `instanceof` stays).
- Fixed 3 real findings: TaintEngine by-ref tainted-map type, BladeXss
  preg-match offset phpdoc, convoluted last-element lookup in XxeAnalyzer.
- Regenerated `phpstan-baseline.neon` (stale entries dropped).
- Deferred: phpstan level bump 6 → max, own-code coverage gate (no driver).

### Fixed (proactive edge-case review)

- Command injection: backtick shell execution with any dynamic part is always
  reported; `pcntl_exec()` added as a sink; `Process::fromShellCommandline()`
  with user input is flagged (unlike array-form `new Process()`).
- Broken access control: exact `$user->can()`/`cannot()` calls count as
  in-body authorization (non-enforcing `Gate::allows()` still does not).
- Open redirect: `redirect()->intended($default)` covered as a sink.
- SSTI: `View::make()/composer()/creator()` covered as sinks.
- Secrets: high-entropy defaults in `env('KEY', ...)` are flagged (placeholder
  denylist included); field-name declarations stay skipped.
- Migration: raw `DROP TABLE/DATABASE` and `TRUNCATE` via `DB::statement()` /
  `DB::unprepared()` participate in the down() restore check.
- SSRF: `?->` nullsafe client calls covered; named `url:`/`uri:`/`path:`
  arguments win over position; `curl_setopt($ch, CURLOPT_URL, $url)` and
  `copy()` added as sinks.
- Path traversal: `Storage::putFile()/putFileAs()`, `unlink()`, `rename()`
  added as sinks.
- SQL injection: column-name injection via `orderBy()`/`orderByDesc()`/`groupBy()`
  with tainted input.
- Mass assignment: `updateOrCreate()`/`firstOrCreate()`/`updateOrInsert()`/
  `firstOrNew()` (both arguments checked) and explicitly empty `$guarded = []`
  (which guards nothing).
- Misconfiguration: insecure session cookie flags (`'secure'/'http_only' =>
  false`, `SESSION_SECURE_COOKIE=false`, `same_site => 'none'`).
- Command injection: `mail()` only flags the dangerous 5th argument
  (`$additional_parameters`, passed to sendmail as CLI flags).
- Unsafe eval: only the callable position of `call_user_func()`/
  `call_user_func_array()` is checked — tainted arguments to a fixed callable
  such as `[$this, 'handle']` are the callee's business.
- Unsafe deserialization: `yaml_parse()`/`yaml_parse_file()`/`yaml_parse_url()`
  added as sinks; `unserialize($data, ['allowed_classes' => false])` skipped.
- Insecure hash: `hash('md5'|'sha1'|'md4', ...)` covered as weak algorithms
  (strong algorithms such as `sha256` stay silent).
- Mass assignment: `Model::unguard()` / `User::unguard()` (resolved through
  `use` imports against scanned models) flagged as global unguard;
  `Model::unguard(false)` skipped as re-guard intent.
- Open redirect: `response(...)->header('Location', $url)` covered as a sink
  (only the `Location` header can redirect).
- Path traversal: `File::`/`Storage::delete()` skipped (deletion cannot
  exfiltrate or include file contents).
- XXE: `XMLReader::open($uri)` / `$reader->open($uri)` covered as sinks.
- Open redirect: `Redirect::intended()` facade covered as a sink.
- XXE: `LIBXML_NOENT` no longer counts as protection (it substitutes
  entities, which enables XXE); only `LIBXML_NONET` /
  `libxml_disable_entity_loader(true)` silence a file.
- Migration: raw `ALTER TABLE ... DROP COLUMN` via `DB::statement()` /
  `DB::unprepared()` participates in the down() restore check.
- Mass assignment: `->forceFill($request->all())` flagged (bypasses
  `$fillable`/`$guarded` by design, even when declared).
- Insecure hash: `rand()`/`mt_rand()`/`uniqid()` for tokens/OTPs/secrets
  flagged (use `random_int()`/`random_bytes()`); non-token uses stay silent.
- Blade: dynamic view names in `@include`/`@extends`/`@includeWhen`/
  `@includeFirst`/`@each` flagged as LFI (literals and `config()` stay silent).
- SSRF: `readfile()`/`file()`/`fsockopen()`/`pfsockopen()`/
  `stream_socket_client()` added as sinks (local-path and literal hosts
  stay silent).
- SSRF: directory listings (`glob()`/`scandir()`, `Storage::files()`) are
  server-side paths — loop variables and `$list[$i]` element reads over them
  stay silent; `$request` arrays still flag.
- Open redirect: `route('home') . $path` concatenations (host pinned by the
  framework), SDK-signed storage URLs (`temporaryUrl()`/`getPresignedUrl()`),
  and `*Safe*` methods (`getSafeUrl()`) skipped; `url($dynamic)` still flags
  (Laravel returns already-valid URLs unchanged).
- Broken access control: route files required from a `*ServiceProvider`
  (`Route::group(['middleware' => ...], fn () => require
  base_path('routes/api.php'))`) inherit the provider's middleware stack.
- Request validation: FormRequest short names resolved through `use` imports.
- Unsafe eval: `$this->callback` handler properties skipped as fixed callables
  (dynamic `[$class, 'method']` pairs still flag).
- SSTI: `in_array()` allow-list gates (inline or literal-array variables)
  silence the guarded variable in the same function.
- Blade: `Number::` helpers and the verified `format_amount_by_*` currency
  formatter family skipped (NumberFormatter float-cast output).
- Traversal: `tempnam()`/`tmpfile()`/`sys_get_temp_dir()` origins are
  server-side temp paths.
- Robustness: `max_file_kb` (default 1024) skips multi-MB data dumps that
  exhaust the parser; the summary reports how many files were skipped.
- Unsafe eval: `assert()` with provably-boolean arguments skipped
  (`instanceof`, comparisons, `empty()`/`isset()`, `is_*()` predicates);
  `app()`/`resolve()` container lookups with all-literal arguments count as
  fixed callables.
- Blade: verified safe renderers (`md_to_html()`, `markdownHelp()`/
  `markdownNotes()`, `excerpt()`) and all-literal ternary branches skipped
  (Elvis still flags).
- Open redirect: fixed-host `sprintf()` formats (literal or literal-assigned
  variable) and no-argument `$request->url()` concatenations skipped.
- Broken access control: FormRequest `authorize()` with real checks counts as
  authorization (`return true` alone still flags).
- Mass assignment: `Model::unguard()` in seed-data paths (seeders, factories,
  migrations, tests) skipped — jobs and console commands still flag.
- Broken access control: route groups nested in top-level installer/maintenance
  guards are descended with the ambient middleware stack.
- Broken access control: credential verification (`$request->authenticate()`,
  `Auth::attempt()`, `hasValidSignature()`, `hash_equals()` capability checks)
  and enforcing gate branches (`if (Gate::denies()) { throw }`) count as
  authorization; bare `Gate::allows()` still flags.
- SSRF: `*sanitiz*()`-gated URLs, `dirname()`/`basename()`/`realpath()` over
  deploy-time values, `__DIR__`/`__FILE__`, and `readdir()`/`opendir()` listings
  skipped; concatenations whose every dynamic leaf is safe stay silent.
- Blade: `safe_raw_html()` family, all-literal ternary branches (Elvis still
  flags), shared local-path hints extended (`tmp`, `temp`, `dest`).
- Secrets: obvious fixtures in test paths skipped (test/fake/example/... markers).
- Secrets: UPPER_SNAKE identifier constants naming their own value
  (`FEATURE_X = 'x_value'`) skipped; every finding carries `evidence`
  (matched prefix, length, entropy, known token prefix, fixture flag).
- Blade: request-derived output stays Error/High, other dynamic output is now
  Warning/Medium.
- MISSING_*_TEST reworded ("no directly associated test detected") and
  downgraded to Info/Low.
- CI gate: `quality_gate.ignore` config + `--ignore=` CLI to hide rules;
  exit codes documented (0 pass / 1 gate failed / 2 internal error).
- HTML report: confidence-weighted Quality Score dashboard (per-dimension
  scores, release gate, Must Fix / Review / Tech Debt buckets).
- Secrets: password-vs-long-literal comparisons (`==`/`===`/`!=`/`!==`, either
  order) reported as master-password pattern; variable-to-variable stays silent.
- SSRF: `$this->prop` (assignments + declaration defaults) origin tracking —
  env()/config()-assigned properties count as deploy-time; request-assigned or
  unassigned properties still flag.
- New rule `INSECURE_COOKIE`: `Cookie::queue()/make()/forever()`, the
  `cookie()` helper and `->cookie()` without an explicit Secure flag
  (Warning) or with literal `false` (Error).
- New rules `SESSION_FIXATION` (login without session rotation in the same
  function) and `WEAK_PASSWORD_POLICY` (`Password::min(N<8)`, short or missing
  `min:` on password fields).
- Report status follows the gate: `fail-on=none` reports `completed` instead
  of a contradictory `failed` (exit code stays 0).
- Open redirect: OAuth SDK `getAuthorizationUrl()` skipped (provider-hosted).
- Password policy: custom-message keys (`'password.min' => '...'`) and
  non-`rules()` positions are not fields; `$rules`-variable indirection is
  followed.
- Configurable heuristics (previously hardcoded): `cache.enabled`/`cache.ttl`
  for the result cache; `analyzers.models_dirs` for Eloquent model lookup
  (DDD layouts); `analyzers.extra_middleware` for custom protective middleware;
  `analyzers.extra_sanitizers` for project-specific Blade escape helpers;
  SARIF `informationUri`/help links use the configured `html.repo_url`.

### Fixed (new public pilots audit)

- Secret skips field-name declarations (`OPT_* = '...'`); eval skips
  preg-validated expressions; SSTI skips template registries; CSRF
  `install/*` downgraded; Blade `Html::` builders and paginator render.

### Added

- Remediation catalog (`src/Remediation/RuleRemediation.php`, 38 rules):
  every finding now teaches the fix — English why + before/after sample,
  rendered in console (why per rule), HTML (fixbox per rule group),
  Markdown (`## Remediation`), JSON (`remediation` per issue) and SARIF
  (`help` + `helpUri` per rule descriptor).

- 3 new OWASP rule families (precision wave 2, each with labeled corpus cases):
  `OWASP_OPEN_REDIRECT` (`owasp.open_redirect` — `redirect()`/`away()`/`to()`
  with dynamic target; skips `route()`/`back()`/literal/`config()` targets and
  literal-arg `url()`; bare-variable/request targets are High confidence,
  method/property/static targets like `$page->getUrl()` are Medium),
  `OWASP_PATH_TRAVERSAL` (`owasp.path_traversal` — file/Storage/download sinks
  with tainted path; skips literals, `basename()`-wrapped, `env()`/`config()`),
  `OWASP_BLADE_XSS` (`owasp.blade_xss` — `{!! ... !!}` with dynamic data in
  `*.blade.php`, collected separately from `resources/`; skips `csrf_field()`,
  `e(...)`, `{{ ... }}` and pre-rendered-HTML naming convention).

### Fixed (Minpo pilots audit)

- Open redirect resolves deploy-time-safe variables (`$url = config(...) . '/x'`)
  and no longer risks crashing on short ternaries; request-derived variables
  stay flagged.
- Broken access control recognizes `checkLogin`-style middleware and never
  treats `guest*` middleware as protection (even `guestAdmin`).

### Fixed (audit wave, validated on 9 pilots)

- Shared local-path naming heuristic (`AbstractAnalyzer::isLocalPathName`,
  incl. `dir`) for SSRF + traversal; request-rooted expressions (`$request`,
  `request()`) never count as local; `include/require` stays strict (LFI).
- Traversal skips path-builder method calls (`absolutePath()`, `pathFor()`,
  `getPathname()`) and `dirname()` with safe args; include resolves
  safe variable origins (config path built from `dirname()` constants).
- Command injection skips `new Process()` with natively typed `array` params,
  ternary-of-arrays commands, and `escapeshellarg()` inside safe expressions.
- SSRF skips fixed-host URLs (`sprintf('https://literal-host/...')`,
  including through same-scope variables) while dynamic subdomains stay flagged.
- Blade XSS skips explicit sanitizers (`sanitizeHtml`, `strip_tags`,
  `htmlspecialchars`, ...), `view_render_event()` theme hooks (440 findings
  in one pilot), paginator `->links()`, and `->renderedHTML`-style properties.
- Open redirect: literal-arg `url()` is safe; bare-variable/request targets
  are High confidence, method targets (`$page->getUrl()`) are Medium.
- Dogfooded the new inline suppression on the package's own reviewed sinks.

### Fixed (POS backend pilot audit)

- Command injection accepts `env()`/`config()` and ternary/coalesce branches
  in safe-command expressions (ImageMagick `$imgMagickCLI` case).
- `DISABLED_CSRF_EXCEPTION_STAR` downgraded to Warning for api-only `api/*`
  exclusions (stateless APIs); broader wildcards stay Critical.

### Fixed (POS edge + cloud pilot audit)

- Command injection skips private-helper params with literal-only call sites
  and `foreach` over constant iterables (service-manager helper case).
- SSTI resolves concatenations of literals (`'front.pos_' . $industry`).
- Broken access control recognizes API-key guards (`*.api.key`,
  `sanctum`, `jwt`, `oauth`).
- Blade XSS skips sanitizer calls, `view_render_event()` hooks, paginator
  `->links()`, `->renderedHTML` properties, and fully HEX-flagged
  `json_encode()` (bare `json_encode($x)` in `<script>` stays flagged).
- SSRF reads Guzzle `$client->request($method, $url)` URLs from the second
  argument and skips deploy-time URL building (`rtrim(env())`, `sprintf()`,
  same-scope variables); dynamic subdomains stay flagged.
- Path traversal covers the `File::` facade (`File::get($request->date)` log
  read was a true positive) plus `dirname()` and path-builder method calls.
- Full re-audit pass: variable-origin resolution now applies to every
  traversal sink branch (not just include/require).

## [1.0.0] - 2026-09-24

### Added

- Inline per-finding suppression: `// quality-checker-ignore RULE[,RULE2]`
  (same line) and `// quality-checker-ignore-next-line RULE` (line above);
  `all` suppresses every rule on that line. Wired into `CustomAnalyzerChecker`
  (summary reports the suppressed count), opt-out via
  `analyzers.inline_suppression => false`.

### Removed

- `ParallelRunner` (and its test): the implementation never actually ran
  checkers in parallel (the `parallel` extension runtime was instantiated but
  unused, no `pcntl` path existed) while nothing referenced it. Real
  multi-process execution needs subprocess isolation and is out of scope;
  `CheckRunner` remains the single sequential, cache-aware entry point.

- OWASP Top-10 (2023) analyzers: broken access control, SSRF, SSTI, misconfiguration, command injection, XXE.
- Confidence model (`low` / `medium` / `high`) with quality tiers (`security` / `quality` / `all`) and `min_confidence` filtering.
- Deduplicator for issues generated from multiple analyzers.
- Migration and route-validation analyzers for Laravel-specific code quality.
- PHPUnit coverage threshold enforcement.
- Dogfooding tools: the package now checks its own codebase (phpcs + phpstan + phpunit).
- GitHub Actions CI and dogfooding workflows for `8.1` / `8.2` / `8.3`.
- Console, JSON, Markdown, HTML and **SARIF** reporters. `--format=sarif` emits
  `quality-report.sarif` (SARIF 2.1.0) for GitHub code-scanning upload: severity
  maps `critical/error → error`, `warning → warning`, `info → note`; rules are
  registered once with highest observed severity; file URIs are relative with
  forward slashes.
- JSON report hardening: `schema_version: 1`, `overall_status`, `fail_on`,
  `min_confidence`, `duration_total`; UTF-8 unescaped.
- Markdown report: table of contents, metadata line, full severity summary,
  top-50 rules, per-file `<details>` issue groups.
- Console report: tier/fail-on/min-confidence header, issues grouped by file,
  50-issue cap per checker with a "… N more" tip, fail remediation tip.
- HTML report: sticky sidebar TOC with scroll-spy, on-page search, severity
  chip filters, interactive severity/rule/hot-file sidebar filters,
  collapsible file groups (`<details>`), clickable file links (`vscode://`
  deep links, or GitHub blob URLs via `html.repo_url` + `html.branch`),
  inline code snippets with ±`html.code_context` context lines, severity
  distribution + top-rule bar charts, sortable tables, dark-mode toggle
  (persisted), print stylesheet, OWASP per-rule drill-down, expand/collapse
  controls, search auto-expands matching file groups.
- Pilot benchmark on a large e-commerce monolith (3,283 files): 1,246 findings / 170 s,
  valid SARIF (12 rules) — recorded in README.
- Auto-provisioning of missing tools: composer-based tools (phpcs/phpstan/phpunit) installed via `composer require --dev` in the target project, and the Trivy binary auto-downloaded into a per-user cache. Disable with `--no-auto-install` / `auto_install_tools => false`.
- Checkers fall back to the package's own `vendor/bin` when a tool is missing but bundled.
- Unified test-coverage detector (`test_coverage.unified`, on by default) that flags source classes
  (controller / service / repository / model) with no matching test, scanning both `tests/Unit` and
  `tests/Feature` from the passed file set.
- Reports now group issues by rule (`Top Rules`) across JSON / Markdown / HTML / console via `IssueGrouper`.
- Expanded test suite to **121 tests** covering every security + OWASP analyzer (positive/negative),
  edge cases (empty project, crash tool, invalid PHP, Windows paths), baseline, cache, parallel runner.
- Code coverage measurement via PCOV/Xdebug in CI (~53% line coverage, core at 100%).

### Changed

- `HtmlReporter` rewritten as a programmatic HTML builder: the Blade-subset template compiler that used `eval()` and `extract()` was removed entirely.
- All user-controlled data in the HTML report is escaped with `htmlspecialchars(..., ENT_QUOTES, 'UTF-8')`.
- Composer audit runs non-interactive with a shorter timeout and reports `error` (instead of `passed`) when the command itself fails (e.g. offline / rate-limited).

### Fixed

- Removed dead code in `TaintEngine` that never reported tainted return values.
- `MassAssignmentAnalyzer` incorrectly calling `getArgs()` on non-call nodes.
- XXE analyzer using a missing `end()` constant reference.
- `HtmlReporter` Blade compiler issues (`@else`, stray `makeView` closure, template branch).
- PHPUnit JUnit report double-counting tests.
- PHPStan project configuration not resolving against the correct baseline.
- Checker exit-code detection not honouring `fail_on` TIER levels.
- `TrivyChecker` reading its own defaults instead of the `trivy.*` config from the context, so `trivy.enabled` was ignored.
- Trivy release asset naming (`windows-64bit`) and default version (`0.74.0`).
- **False-positive wave 1 (route-middleware BAC):** `OWASP_BROKEN_ACCESS_CONTROL`
  now resolves route middleware (`Route::middleware`, `->middleware()` chains,
  `Route::group([...])` incl. nesting and direct static calls,
  `Route::controller()` groups with bare-string actions, `resource/apiResource`,
  cross-file `require` inside group closures), legacy `['uses' => 'FQCN@method']`
  array syntax, and FQCN action keys via `use`-import resolution
  (config `analyzers.owasp.route_middleware`, default on). E-commerce pilot
  453 → 150, HRM pilot 45 → 1.
- **False-positive wave 2 (SSRF/command/SSTI/hash/migration):** SSRF skips test
  paths, `fopen()` write modes, local-path names/helpers, `->getRealPath()` /
  `->getPathname()`, `env()`/`config()` lookups, and no longer treats the
  `new GuzzleHttp\Client([...])` constructor as a URL sink; command injection
  skips `escapeshellarg()`/`escapeshellcmd()`, array-form `new Process()` and
  deploy-time-safe concatenations (`PHP_BINARY`, path helpers, same-function
  safe variables); SSTI skips literal-assigned variables and non-public helpers
  with literal-only call sites; `INSECURE_HASH` skips HIBP k-anonymity clients;
  `MIGRATION_DESTRUCTIVE_UP` skips down()-restored drops and index/constraint
  drops. Validated on 8 pilots (internal HRM/LMS/business apps, e-commerce
  monolith + package, wiki, PRM, status page).
- **Stale cache:** `ResultCache` keys now include a hash of the analyzer/checker
  source, so package upgrades can never serve results computed by older code.
- Labeled precision/recall corpus (`tests/Unit/AnalyzerMetricsTest.php`, 26
  cases, currently 1.000 / 1.000) guards the FP reductions against regression.

## [0.1.0] - 2026-09-20

### Added

- Laravel artisan command `quality:check` with a quality gate over phpcs, phpstan, phpunit, composer audit and custom PHP-Parser analyzers.
- Security analyzers for SQL injection, unsafe eval, hardcoded secrets, mass assignment, unsafe deserialization, insecure hashing, Laravel taint and disabled CSRF.
- Test-coverage heuristics (missing controller / service / model tests, missing feature coverage, tests without assertions).
- Convention heuristics (naming conventions, TODO/FIXME, dead code, Laravel pitfalls).
- Baseline generation and filtering, JSON / Markdown / console reporters, exit codes and `--fail-on` control.
- Configuration via `config/quality-checker.php`.

[0.1.0]: https://github.com/your-org/quality-checker/releases/tag/0.1.0
