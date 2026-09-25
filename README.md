<div align="center">

# VietVang Quality Checker

**Một cổng kiểm tra chất lượng (quality gate) toàn diện cho Laravel** —
_A comprehensive Laravel quality gate._

Wraps `phpcs`, `phpstan`, `phpunit`, `composer audit` and `trivy` into a single
Artisan command, and adds custom PHP-Parser analyzers for **security**, **missing
tests** and **code conventions** — all with machine-readable reports and
standardised exit codes for CI.

</div>

---

## Overview / Tổng quan

`quality:check` is a single Artisan command that runs the whole quality pipeline
and produces one of: a console table, JSON, HTML or Markdown report. It returns
a predictable exit code you can wire directly into your CI pipeline.

The package philosophy:

- **Wrap, don't rewrite** — standard tools are invoked via their CLI and their
  output is parsed.
- **Custom analyzers only where needed** — security heuristics, missing-test
  detection and convention rules are implemented with PHP-Parser over the AST.
- **Zero-config by default** — it runs right after install, and is configurable
  to disable or extend rules.
- **CI-friendly** — non-zero exit on failure, JSON machine-readable output.

---

## Features / Tính năng

- One command to rule them all: `php artisan quality:check`
- Multiple report formats: `console`, `json`, `html`, `md`, `sarif` (or `all`)
- Enterprise HTML report: collapsible file groups, clickable file links
  (`vscode://` or GitHub blob), inline code snippets, severity/top-rule
  charts, sortable tables, dark mode, print stylesheet, OWASP drill-down
- Standardised exit codes for CI gates
- Dependency security audit (`composer audit`)
- Optional filesystem security scan (`trivy`)
- Custom AST analyzers for security, missing tests and conventions
- Baseline support to "accept" existing issues and only report new ones
- Auto-fix of fixable issues via `phpcbf` (`--fix`)
- Cache for analyzer results (`--no-cache` to bypass)
- CI mode (`--ci`) and JSON shortcut (`--json`)

---

## Requirements / Yêu cầu

| Requirement | Version |
|---|---|
| PHP | `^8.1` |
| Laravel | `10`, `11`, `12` (`illuminate/console` & `illuminate/support` `^10.0|^11.0|^12.0`) |
| Composer | `2.4+` (for `composer audit`) |

Optional tools (skipped with a hint if missing): `squizlabs/php_codesniffer`,
`phpstan/phpstan`, `phpunit/phpunit`, `trivy`.

---

## Installation / Cài đặt

Requirements: PHP `^8.1`, Laravel `10|11|12`, and Composer `2.4+`.

```bash
composer require vietvang/quality-checker
```

The service provider is auto-discovered. Publishing the config is optional, but
recommended when you want to change paths, tiers, tool settings, or enable Trivy:

```bash
php artisan vendor:publish --tag=quality-checker-config
```

This creates `config/quality-checker.php`.

### Using a local clone during development

When developing the checker itself, clone it next to the Laravel application:

```bash
git clone https://github.com/VietVang-JSC/vv-laravel-checker.git
cd vv-laravel-checker
composer install
```

From the Laravel application's directory, register the local checkout and
install the package from that path:

```bash
composer config repositories.quality-checker path ../vv-laravel-checker
composer require vietvang/quality-checker:@dev
php artisan vendor:publish --tag=quality-checker-config
php artisan quality:check --tier=security --only=custom,composer_audit
```

The relative path must point from the Laravel application's directory to the
cloned checker directory. Composer creates a symlink/junction where supported,
so source changes in the clone are immediately used by the application. After
pulling package changes, run:

```bash
composer update vietvang/quality-checker --with-dependencies
```

For a normal application installation, omit the path repository and use the
stable package version instead:

```bash
composer require vietvang/quality-checker
```

---

## Quick Start (5 minutes) / Bắt đầu nhanh

Run the security scan first. It is the safest first run because it does not
require every optional tool to be installed:

```bash
php artisan quality:check --tier=security --only=custom,composer_audit
```

Then run the complete local gate:

```bash
php artisan quality:check
```

To generate all report formats in a predictable directory:

```bash
php artisan quality:check --format=all --output=reports/quality-checker
```

The command returns exit code `0` when the selected threshold passes and a
non-zero code when the gate fails. Use `--fail-on=none` when reviewing findings
without failing the shell command.

### Recommended rollout for an existing project

Do not block the team on every legacy finding on the first day:

```bash
# Review the current state without failing
php artisan quality:check --format=all --fail-on=none

# Accept the current findings as a starting point
php artisan quality:check --baseline-generate

# From now on, fail only on new findings
php artisan quality:check --ci --baseline-file=baseline.json
```

Commit `baseline.json` so all developers and CI use the same starting point.
Only run `--baseline-update` after reviewing the new findings; it accepts all
current findings again.

### Tool installation behavior

Auto-install is enabled by default. If `phpcs`, `phpstan`, or `phpunit` is
missing, the checker may add the corresponding Composer dev dependency to the
target project. Trivy is downloaded to the user cache and does not modify the
project. For read-only or air-gapped environments, use:

```bash
php artisan quality:check --no-auto-install
```

Missing optional tools are then reported as `skipped` instead of being installed.

---

## Options Reference / Bảng tham chiếu tuỳ chọn

| Option | Description / Mô tả | Default / Mặc định |
|---|---|---|
| `--format=...` | Comma-separated report formats: `console`, `json`, `html`, `md`, `sarif`, or `all` (runs all five). | `console` |
| `--only=...` | Only run these checkers (comma-separated): `phpcs`, `phpstan`, `phpunit`, `composer_audit`, `trivy`, `custom`. | all checkers |
| `--exclude=...` | Skip these checkers (comma-separated). | — |
| `--path=*` | Override scan paths (repeatable, e.g. `--path=app --path=routes`). | from config |
| `--fail-on=severity` | Fail threshold: `none`, `info`, `warning`, `error`, `critical`. | `error` |
| `--tier=...` | Quality gate tier: `security`, `quality`, `all`. | from config (`quality`) |
| `--min-confidence=...` | Minimum confidence to report: `low`, `medium`, `high`. | from config (`low`) |
| `--output=...` | Output directory for report files. | `reports/quality-checker` (from config) |
| `--no-cache` | Ignore cached analyzer/checker results. | off |
| `--no-auto-install` | Disable auto-installing missing tools (phpcs/phpstan/phpunit/trivy). | off |
| `-q`, `--quiet` | Symfony Console's built-in quiet flag — prints the summary line only. | off |
| `--json` | Shortcut for `--format=json`. | off |
| `--ci` | CI mode: JSON output, `fail-on=error`, no progress. | off |
| `--fix` | Auto-fix fixable issues (currently `phpcbf` only). | off |
| `--baseline-generate` | Write the current issues to the baseline file. | off |
| `--baseline-update` | Rewrite the baseline with all current issues. | off |
| `--baseline-file=...` | Baseline file path. | `baseline.json` (project root) |

> Note: `--json` implies the JSON reporter, while `--ci` adds the JSON reporter
> automatically. `--format=all` maps to `console,json,html,md,sarif`.
> `sarif` emits `quality-report.sarif` (SARIF 2.1.0) for GitHub code scanning upload.

---

## Exit Codes / Mã thoát

| Code | Meaning / Ý nghĩa |
|---|---|
| `0` | Pass — no issue exceeds the `--fail-on` threshold. |
| `1` | Issues found that exceed the threshold (default `error` and above). |
| `2` | Environment error (missing tool, config error). |
| `3` | Runtime error inside the package itself. |

---

## Checkers / Bộ kiểm tra

| Checker | Command wrapped | Notes |
|---|---|---|
| `phpcs` | `vendor/bin/phpcs` | Coding standard (default `PSR12`). |
| `phpstan` | `vendor/bin/phpstan` | Static analysis (default level `5`). |
| `phpunit` | `vendor/bin/phpunit` | Test suite, failures become issues. Also parses Clover coverage and flags `PHPUNIT_LOW_COVERAGE` when below `phpunit.coverageThreshold` (default 60%). |
| `composer_audit` | `composer audit` | Dependency security advisories. |
| `trivy` | `trivy fs` / `trivy config` | Optional filesystem/IaC security scan (disabled by default). |
| `custom` | PHP-Parser AST | Custom analyzers: security, test coverage, conventions. |

When an optional tool is not installed, the corresponding checker reports
`skipped` with a hint on how to install it.

---

## Custom Analyzer Rules / Bảng rule phân tích

### Security (analyzers/security)

| Rule ID | Severity | What it detects / Phát hiện |
|---|---|---|
| `SQL_INJECTION` | Critical | Tainted request input flowing into raw queries (`DB::select`, `whereRaw`, ...). |
| `UNSAFE_EVAL` | Critical | `eval()` / `assert()` with dynamic data. |
| `HARDCODED_SECRET` | Critical | Hardcoded secrets/API keys (`sk-`, `AIza`, `AKIA`, private keys, ...). |
| `MASS_ASSIGNMENT` | Error | `Model::create($request->all())` without `$fillable`/`$guarded`. |
| `UNSAFE_UNSERIALIZE` | Critical | `unserialize()` of untrusted data. |
| `INSECURE_HASH` | Warning | Weak hashes (`md5()`, `sha1()`) used for passwords. |
| `LARAVEL_TAINT` | Error | Tainted variable interpolation into query builder / `whereRaw`. |
| `DISABLED_CSRF` | Warning / Critical | CSRF protection disabled (`@csrf`, `VerifyCsrfToken` bypassed). |
| `TAINT_SQL_INJECTION` / `TAINT_COMMAND_INJECTION` / `TAINT_EVAL` / `TAINT_UNSAFE_SERIALIZE` | Critical | Data-flow taint tracking engine (disabled by default). |

The `taint_engine` rule is disabled by default in the config.

### Test coverage (analyzers/test_coverage)

| Rule ID | Severity | Confidence | What it detects / Phát hiện |
|---|---|---|---|
| `MISSING_CONTROLLER_TEST` | Warning | low | Controller with no corresponding test (unit or feature). |
| `MISSING_SERVICE_TEST` | Warning | low | Service with no corresponding test. |
| `MISSING_REPOSITORY_TEST` | Warning | low | Repository with no corresponding test. |
| `MISSING_MODEL_TEST` | Warning | low | Model with custom logic (>= 3 methods) but no test. |

These come from the **unified `test_coverage.unified`** detector (on by default) which
classifies source classes and checks for a matching `*Test.php` in either `tests/Unit`
or `tests/Feature` (mirrored namespace or flat layout).

Opt-in heuristics (off by default): `missing_feature_coverage` (route-level),
`test_without_assert` (test method with no assertion).

### Convention (analyzers/convention)

| Rule ID | Severity | What it detects / Phát hiện |
|---|---|---|
| `NAMING_CONVENTION` | Info | Class/method/const names that deviate from conventions. |
| `TODO_FIXME` | Info | Leftover `TODO` / `FIXME` / `HACK` markers. |
| `DEAD_CODE` | Info | Methods/params never used (heuristic). |
| `LARAVEL_PITFALL` | Warning | Laravel anti-patterns (`DB::raw` outside migrations, `env()` outside config, leftover `dd()`/`dump()`, `sleep` in tests, ...). |

### OWASP Top 10 (2023) — analyzers/owasp

| Rule ID | Severity | Confidence | OWASP | What it detects / Phát hiện |
|---|---|---|---|---|
| `OWASP_BROKEN_ACCESS_CONTROL` | Error | high | A01 | Mutating controller method (`store/update/delete/...`) with no visible `authorize`/`Gate`/`abort`/middleware. |
| `OWASP_SSRF` | Error | high | A10 | URL from user input flows into `file_get_contents`/`fopen`/`Http::`/Guzzle. |
| `OWASP_SSTI` | Error | high | A03 | Dynamic template arg flows into `view()`/`Blade::render`. |
| `OWASP_MISCONFIGURATION` | Warning | high | A05 | Debug mode enabled, permissive CORS wildcard, placeholder/empty secrets (config files only). |
| `OWASP_COMMAND_INJECTION` | Critical | high | A03 | User input flows into `system`/`exec`/`shell_exec`/`Process`. |
| `OWASP_XXE` | Error | high | A05 | `simplexml_load_*`/`DOMDocument`/`SimpleXMLElement` without entity-loader guard. |

All OWASP rules are on by default.

### Laravel-specific (analyzers/laravel)

| Rule ID | Severity | Confidence | What it detects / Phát hiện |
|---|---|---|---|
| `MIGRATION_MISSING_DOWN` | Warning | medium | Migration defines `up()` but no `down()` — not reversible. |
| `MIGRATION_DESTRUCTIVE_UP` | Warning | medium | Destructive schema op (`dropTable`/`dropColumn`/...) in `up()` without re-creation. |
| `ROUTE_MISSING_VALIDATION` | Warning | medium | Mutating action (`store`/`update`/`delete`/...) with no `$request->validate`/FormRequest. |

The `laravel` group is on by default (medium confidence).

### Confidence & Tiering / Mức tin cậy & tầng chất lượng

Every issue carries a **confidence**: `high` | `medium` | `low`.

- `high` → safe to gate CI (OWASP, taint, hardcoded secret, composer audit).
- `medium` → fairly reliable warning (`env()` outside config, `dd()` in app, insecure hash).
- `low` → heuristic hints, hidden unless you opt in (dead code, missing test, naming, todo).

Convention heuristics (`convention.*`) are **off by default** to avoid noise.
The unified test-coverage detector is enabled by default but emits low-confidence
warnings; raise `--min-confidence=high` or use the `security` tier when you want
to focus on security findings only.

The **tier** controls what the gate fails on:

| Tier | Fails on | Use for |
|---|---|---|
| `security` | high-confidence security issues only (OWASP/taint/secret/composer_audit) | security CI gate |
| `quality` | medium+ high error/critical (incl. phpcs/phpstan/phpunit) | standard CI gate (default) |
| `all` | everything surfaced | local dev |

`--min-confidence` filters what is reported; `--tier` filters what the exit code fails on.

---

## Pilot benchmark (real-world)

Custom analyzers only (phpcs/phpstan/phpunit excluded), `tier=security`,
`fail-on=none`, cold runs without cache. Quality is pinned by a labeled
corpus (`tests/Unit/AnalyzerMetricsTest.php`): **precision 1.000 / recall 1.000**
across 63 true/false-positive cases (24 TP + 39 TN), so the reductions below
cannot regress silently.

| Pilot | Stack | Files | Before | After | Signal left |
|---|---|---|---|---|---|
| Bagisto / LienHoaEc | Laravel 11 e-commerce | 3,283 | 1,246 (7 / 466 / 773) | **1,079** (3 / 303 / 773) | 101 blade (raw display, review) + public routes + Docs sample |
| SiroHRM | Laravel 12 HRM | 526 | 191 (5 / 55 / 131) | **135** (1 / 5 / 129) | 4 open redirects + coverage |
| SiroLingo | Laravel 12 LMS | ~600 | 176 (0 / 2 / 174) | **203** (0 / 29 / 174) | 21 blade (sanitized display, review) + 8 redirect/traversal |
| quanlyinan3m | Laravel (internal) | ~500 | 62 (0 / 1 / 61) | **79** (0 / 18 / 61) | 18 blade (import display, review) |
| BookStack | Laravel docs wiki | ~1,400 | 186 (2 / 30 / 154) | **265** (2 / 111 / 152) | 75 redirect (16 high auth flow) + 21 BAC API |
| Monica | Laravel PRM (DDD) | ~1,800 | 387 (3 / 7 / 377) | **383** (2 / 6 / 375) | 1 true `exec()` on param + validation debt |
| Aimeos | Laravel e-commerce pkg | ~200 | — | **3** (0 / 2 / 1) | JSON:API auth-in-core + 1 require review |
| Cachet | Laravel status page | ~100 | — | **3** (0 / 0 / 3) | CORS wildcard + coverage |
| laravel-check (dogfood) | Package itself | ~200 | 37 | **5** (3 / 1 / 1) | all intended (vuln fixtures + test secret) |
| DeltaPOS edge-box | Laravel POS edge | ~400 | — | **100** (0 / 55 / 45) | 39 blade + 10 unauth API (backup/printer review) |
| DeltaPosWeb | Laravel POS cloud | ~500 | — | **182** (1 / 139 / 42) | 104 blade + 22 server-fetch review + 1 true open redirect |
| free-pos-backend | Laravel POS backend | ~700 | — | **254** (1 / 50 / 203) | coverage debt + 20 BAC (JWT groups resolved) |

*(severity split: critical / error / warning)*

Biggest single win: `OWASP_BROKEN_ACCESS_CONTROL` on Bagisto **453 → 150** —
actions protected by route middleware, `Route::controller()` groups and
cross-file `require` are now resolved; FQCN keys keep same-named Admin/Shop
controllers apart (see [docs/false-positives.md](docs/false-positives.md)).

Repeat runs are near-instant via the result cache (1 h TTL, keyed by file-set
hash + tool config **+ analyzer code version**, so package upgrades never
serve stale results).

---

## Auto-provisioning missing tools / Tự cài tool thiếu

By default the checker **self-provisions** missing tools instead of just skipping
them:

- **phpcs / phpstan / phpunit** — installed via `composer require --dev` inside
  the target project when missing. (Slow on very large projects; disable with
  `--no-auto-install` or `auto_install_tools => false`.)
- **trivy** — downloaded as a cached binary (GitHub releases) into a per-user
  cache directory, never touching the target project. Default version `0.74.0`
  (override with `trivy.version`). Binary is cached, so repeat runs are offline.
- If auto-install is off or fails, a checker uses a tool already available in the
  target project's `vendor/bin`; otherwise it is reported as `skipped` with an
  install hint.

Config: `auto_install_tools => true` (default). Disable for air-gapped/read-only
projects.

---

## Troubleshooting / Xử lý lỗi thường gặp

### PHPUnit exits with code 255 or runs out of memory

The checker runs the target project's `vendor/bin/phpunit`. Large Laravel test
suites may need more than PHP's default CLI memory limit. Increase the CLI
`memory_limit` in the PHP installation used by the project, then run the check
again. Confirm the test suite independently first:

```bash
php -d memory_limit=1G vendor/bin/phpunit --no-coverage
php artisan quality:check --only=phpunit
```

### The first report contains too many legacy findings

Use the baseline workflow above instead of lowering security confidence. A
baseline hides only the exact existing findings; new findings still appear.

### A tool is missing or the project is read-only

Run the custom analyzers and dependency audit without provisioning tools:

```bash
php artisan quality:check --only=custom,composer_audit --no-auto-install
```

### A finding may be a heuristic false positive

Custom analyzers are static heuristics and do not replace a manual security
review. Check the file and line in the report, then use a reviewed baseline or
adjust the analyzer configuration rather than suppressing all security rules.
See [`docs/false-positives.md`](docs/false-positives.md) for a per-rule guide.

---

## Baseline Workflow / Quy trình Baseline

Baseline lets you "accept" the issues currently present in a project, so that
only **new** issues are reported from then on. This is useful when introducing
`quality-checker` to a project that already has many issues you do not want to
fix immediately.

### 1. Generate a baseline from the current results

```bash
php artisan quality:check --format=json --output=reports/quality-checker
php artisan quality:check --baseline-generate
```

This writes a `baseline.json` file at the project root.

### 2. Update the baseline

```bash
php artisan quality:check --baseline-update
```

This overwrites the baseline with **all** current issues (every severity). Only
use it when you are sure the current state is the desired one.

### 3. Use a custom baseline file

```bash
php artisan quality:check --baseline-file=reports/baseline.json
```

### How it works

The baseline file is a simple JSON array of signatures (each signature is
`md5(rule|file|line|message)`):

```json
{
  "generated_at": "2026-09-20T10:00:00+07:00",
  "baseline": [
    "9f2c1d8a3b7e4f5a..."
  ]
}
```

When a baseline is loaded, issues matching a signature are excluded from the
report.

### Baseline in CI

For a shared team baseline, commit `baseline.json` to the repository so the whole
team agrees on the quality threshold. If each developer should maintain their own,
add `baseline.json` to `.gitignore` instead.

See [`docs/baseline.md`](docs/baseline.md) for more details.

---

## Auto-fix / Tự sửa lỗi

```bash
php artisan quality:check --fix
```

`--fix` runs `phpcbf` to auto-fix fixable coding-standard issues on the scanned
paths. If `phpcbf` is not installed, it prints a warning. Only coding-standard
issues are fixable; the custom analyzers are informational only.

---

## CI Integration / Tích hợp CI (GitHub Actions)

The recommended CI workflow uses `--ci` (JSON output + `fail-on=error`) and
uploads the report as an artifact.

```yaml
name: Quality

on: [push, pull_request]

jobs:
  quality:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: shivammathur/setup-php@v2
        with:
          php-version: '8.2'
          coverage: none
      - run: composer install --prefer-dist --no-progress
      - name: Quality Check
        run: php artisan quality:check --ci
        env:
          PHP_VERSION: 8.2
      - name: Upload report
        uses: actions/upload-artifact@v4
        with:
          name: quality-report
          path: reports/quality-checker/quality-report.json
```

The job fails when the exit code is non-zero, which happens when any issue
reaches the `error` threshold (the default for `--ci`).

### Upload findings to GitHub code scanning (SARIF)

`--format=sarif` emits a SARIF 2.1.0 file that GitHub Advanced Security can
ingest, so security findings surface directly on the PR as code-scanning alerts:

```yaml
      - name: Quality Check (SARIF)
        run: php artisan quality:check --format=sarif,console --fail-on=none
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: reports/quality-checker/quality-report.sarif
          category: vietvang-quality-checker
```

Severity mapping: `critical`/`error` → `error`, `warning` → `warning`,
`info` → `note`. Each rule is registered once with its highest observed
severity, and OWASP/taint/security rules are tagged accordingly.

---

## Pre-commit Hook / Hook trước khi commit

Pre-commit hook stubs are provided at `resources/stubs/pre-commit` and
`resources/stubs/pre-commit.ps1` (Unix and PowerShell respectively). Install the
relevant one into your project's `.git/hooks/` (or a hooks-manager like
[`pre-commit`](https://pre-commit.com)) to run the quality gate before every
commit.

---

## Developing & Testing the Package / Phát triển & kiểm thử package

Clone the repository and install dependencies:

```bash
composer install
```

Run the test suite:

```bash
vendor/bin/phpunit
```

To regenerate the optimized autoloader after adding classes:

```bash
composer dump-autoload --optimize
```

Validate the `composer.json`:

```bash
composer validate --no-check-publish
```

---

## License / Giấy phép

[MIT](LICENSE) © 2026 VietVang
