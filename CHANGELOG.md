# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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
- Pilot benchmark on Bagisto/LienHoaEc (3,283 files): 1,246 findings / 170 s,
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
  (config `analyzers.owasp.route_middleware`, default on). Bagisto 453 → 150,
  SiroHRM 45 → 1.
- **False-positive wave 2 (SSRF/command/SSTI/hash/migration):** SSRF skips test
  paths, `fopen()` write modes, local-path names/helpers, `->getRealPath()` /
  `->getPathname()`, `env()`/`config()` lookups, and no longer treats the
  `new GuzzleHttp\Client([...])` constructor as a URL sink; command injection
  skips `escapeshellarg()`/`escapeshellcmd()`, array-form `new Process()` and
  deploy-time-safe concatenations (`PHP_BINARY`, path helpers, same-function
  safe variables); SSTI skips literal-assigned variables and non-public helpers
  with literal-only call sites; `INSECURE_HASH` skips HIBP k-anonymity clients;
  `MIGRATION_DESTRUCTIVE_UP` skips down()-restored drops and index/constraint
  drops. Validated on 8 pilots (SiroHRM, Bagisto, SiroLingo, Aimeos,
  quanlyinan3m, BookStack, Monica, Cachet).
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