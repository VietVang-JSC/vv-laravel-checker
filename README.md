<div align="center">

# Rampart Quality Checker

**A comprehensive quality gate for Laravel** —
_A comprehensive Laravel quality gate._

Wraps `phpcs`, `phpstan`, `phpunit`, `composer audit` and `trivy` into a single
Artisan command, and adds custom PHP-Parser analyzers for **security**, **missing
tests** and **code conventions** — all with machine-readable reports and
standardised exit codes for CI.

</div>

---

## Overview

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

## Features

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

## Requirements

| Requirement | Version |
|---|---|
| PHP | `^8.1` |
| Laravel | `9`, `10`, `11`, `12` (`illuminate/console` & `illuminate/support` `^9.0|^10.0|^11.0|^12.0`) |
| Composer | `2.4+` (for `composer audit`) |

Optional tools (skipped with a hint if missing): `squizlabs/php_codesniffer`,
`phpstan/phpstan`, `phpunit/phpunit`, `trivy`.

---

## Installation

Requirements: PHP `^8.1`, Laravel `9|10|11|12`, and Composer `2.4+`.

```bash
composer require rampart/quality-checker
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
git clone https://github.com/thiennhant95/Rampart.git
cd Rampart
composer install
```

From the Laravel application's directory, register the local checkout and
install the package from that path:

```bash
composer config repositories.quality-checker path ../Rampart
composer require rampart/quality-checker:@dev
php artisan vendor:publish --tag=quality-checker-config
php artisan quality:check --tier=security --only=custom,composer_audit
```

The relative path must point from the Laravel application's directory to the
cloned checker directory. Composer creates a symlink/junction where supported,
so source changes in the clone are immediately used by the application. After
pulling package changes, run:

```bash
composer update rampart/quality-checker --with-dependencies
```

For a normal application installation, omit the path repository and use the
stable package version instead:

```bash
composer require rampart/quality-checker
```

---

## Two Ways to Run

The same engine, the same analyzers, the same reports and the same exit codes.
Two entry points, because the situations they serve are genuinely different.

| | **Artisan command** | **Standalone binary** |
|---|---|---|
| Command | `php artisan quality:check` | `php bin/quality-check <target-dir>` |
| Lives in | your app (`vendor/rampart/quality-checker`) | the tool's own checkout, scanning any target |
| Needs `vendor/` in the target | yes | **no** |
| Needs a bootable Laravel app | yes | no — static sources only |
| Config source | published `config/quality-checker.php` | the tool's own config, plus CLI flags |
| Default scan scope | `paths` from config (`app`, `routes`, `database`, `config`, `tests`) | `app src routes config database tests resources packages` found in the target |
| Default checkers | all six | **`custom` only** — the wrapped tools need the target's own vendor |
| Reports go to | `base_path()/reports/quality-checker` | `<target>/reports/quality-checker` |
| Report version stamp | resolved package version | resolved package version (identical) |

**Use the Artisan command** for your own application: it has the target's
dependencies, its config file, its `phpunit` suite, and the full option set
including `--fix`, `--ignore`, `--ci` and `--json`.

```bash
composer require rampart/quality-checker
php artisan quality:check
```

**Use the standalone binary** when the target cannot take the dependency —
version conflicts, a legacy toolchain, a read-only mount, a codebase you are
auditing but not building. It needs nothing from the target beyond PHP.

```bash
git clone https://github.com/thiennhant95/Rampart.git
cd Rampart && composer install
php bin/quality-check /path/to/other/project --tier=security --fail-on=none
```

Both write the same five report formats and both return `0` / `1` / `2` for
pass / gate-failed / environment-error, so a CI job can switch between them
without changing how it interprets the result.

Options that exist on only one entry point are marked in the
[Options Reference](#options-reference).

---

## Quick Start (5 minutes)

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

### Viewing the HTML report

Open `reports/quality-checker/quality-report.html` directly in a browser — the
report is fully self-contained (no network needed) and works from `file://`.
File links use `vscode://` deep links (require VS Code); set
`html.repo_url` in the published config to get GitHub blob links instead.

### Standalone scan (no install in the target project)

When the target cannot install the package (version conflicts, legacy
toolchain), scan it without touching it — no `vendor`, no `artisan` needed
in the target:

```bash
php bin/quality-check /path/to/project --format=all --tier=security --fail-on=none
```

Defaults to `--only=custom` (static analyzers only). Reports land in
`<target>/reports/quality-checker` unless `--output=` overrides it.

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

Auto-install is **off** by default. If `phpcs`, `phpstan`, or `phpunit` is
missing, the checker reports it as `skipped` and prints the command to install
it manually. This is deliberate: installing means running `composer require
--dev` inside your project, which edits `composer.json` and `vendor/` before you
have seen a single finding, with no undo.

To opt in:

```php
// config/quality-checker.php
'auto_install_tools' => true,
```

or per run, by dropping `--no-auto-install`. Trivy is downloaded to the user
cache and does not modify the project either way.

---

## Options Reference

"Artisan" means `php artisan quality:check`, "Standalone" means
`php bin/quality-check <target-dir>`.

| Option | Applies to | Description | Default |
|---|---|---|---|
| `--format=...` | both | Comma-separated report formats: `console`, `json`, `html`, `md`, `sarif`, or `all` (runs all five). | `console` |
| `--only=...` | both | Only run these checkers (comma-separated): `phpcs`, `phpstan`, `phpunit`, `composer_audit`, `trivy`, `custom`. | Artisan: all six. Standalone: `custom` |
| `--exclude=...` | both | Skip these checkers (comma-separated). | — |
| `--tier=...` | both | Quality gate tier: `security`, `quality`, `all`. | from config (`quality`) |
| `--min-confidence=...` | both | Minimum confidence to report: `low`, `medium`, `high`. | from config (`low`) |
| `--fail-on=severity` | both | Fail threshold: `none`, `info`, `warning`, `error`, `critical`. | `error` |
| `--output=...` | both | Output directory for report files. | `reports/quality-checker` (from config) |
| `--no-cache` | both | Ignore cached analyzer/checker results. | off |
| `--path=*` | both, different meaning | Artisan: replaces the configured `paths`. Standalone: restricts the scan to these sub-directories of the target. Repeatable. | from config / auto-detected |
| `--exclude-path=*` | both | Skip files matching these path patterns (repeatable, e.g. `--exclude-path='*/stubs/*'`). Merged with `analyzers.exclude_paths`. | from config |
| `--baseline-generate` | both | Write the current issues to the baseline file. | off |
| `--baseline-update` | both | Rewrite the baseline with all current issues. | off |
| `--baseline-file=...` | both | Baseline file path. | `baseline.json` at the project / target root |
| `--profile` | both | Write `profile.json` (timers, parse amplification) next to the reports. Findings unchanged. | off |
| `--help` | both | Print usage. Standalone prints its own list; Artisan uses Symfony Console's. | — |
| `--ignore=...` | Artisan | Skip these rules (comma-separated, e.g. `MISSING_MODEL_TEST`), merged with `quality_gate.ignore`. Not in standalone: there is no config file to merge with, so use `analyzers.exclude_paths` or a baseline. | — |
| `--no-auto-install` | Artisan | Disable auto-installing missing tools (phpcs/phpstan/phpunit/trivy). Standalone never installs anything. | off |
| `--fix` | Artisan | Auto-fix fixable issues (currently `phpcbf` only). Needs the target's vendor, so it is not offered in standalone. | off |
| `--json` | Artisan | Shortcut for `--format=json`. In standalone, pass `--format=json`. | off |
| `--ci` | Artisan | CI mode: JSON output, `fail-on=error`, no progress. In standalone, pass `--format=json --fail-on=error`. | off |
| `-q`, `--quiet` | Artisan | Symfony Console's built-in quiet flag — prints the summary line only. Standalone takes `-q` through Symfony Console as well. | off |

> Note: `--json` implies the JSON reporter, while `--ci` adds the JSON reporter
> automatically. `--format=all` maps to `console,json,html,md,sarif`.
> `sarif` emits `quality-report.sarif` (SARIF 2.1.0) for GitHub code scanning upload.

### Path exclusion (`analyzers.exclude_paths`)

`--exclude` filters *checker names*; `analyzers.exclude_paths` filters *files*, and
is the only way to keep the custom analyzers out of a directory. The shipped
default is `['*/fixtures/*']`: code under a `fixtures/` directory exists to be
vulnerable, so reporting it is noise rather than signal — a project whose test
suite keeps vulnerable samples there would otherwise have to baseline them or
disable the rules.

```php
// config/quality-checker.php
'analyzers' => [
    'exclude_paths' => ['*/fixtures/*', 'tests/Fixtures', 'database/seeds/*'],
],
```

Two forms are accepted, both case-insensitive and separator-insensitive:

| Form | Example | Matches |
|---|---|---|
| glob (`*` or `?`) | `*/fixtures/*` | the whole path, via `fnmatch()` |
| plain segment sequence | `tests/fixtures` | anywhere in the path, on `/` boundaries only — never `fixturesx` |

Excluded files are counted in the `custom` checker summary (`N file(s) excluded
by analyzers.exclude_paths`), so a scan never hides scope silently. Use `[]` to
scan everything.

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Pass — no issue exceeds the `--fail-on` threshold. |
| `1` | Issues found that exceed the threshold (default `error` and above). |
| `2` | Bad invocation or setup (missing target, unreadable config). |
| `3` | Runtime error inside the package itself. |

---

## Checkers

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

## Custom Analyzer Rules

43 rule ids across 5 groups. Every row below is verified against
`src/Result/RuleIds.php` by `RuleDocsTest`, so this table cannot drift from what
the analyzers actually emit — an id that does not exist, or a rule that ships
undocumented, fails the build.

Severity is what the rule emits; where a rule emits more than one, both are
listed. Confidence is the noise rating: `high` is safe to gate CI on, `low` is a
heuristic hint. See [Confidence & Tiering](#confidence--tiering).

### Security (`analyzers/security`)

| Rule ID | Severity | Confidence | What it detects |
|---|---|---|---|
| `SQL_INJECTION` | Critical | high | Tainted request input flowing into raw queries (`DB::select`, `whereRaw`, ...). |
| `UNSAFE_EVAL` | Critical | high | `eval()` / `assert()` with dynamic data. |
| `HARDCODED_SECRET` | Critical | high | Hardcoded secrets and API keys (`sk-`, `AIza`, `AKIA`, private key blocks, default credentials). |
| `UNSAFE_UNSERIALIZE` | Critical | high | `unserialize()` of untrusted data. |
| `MASS_ASSIGNMENT` | Error, Warning | high, medium | `Model::create($request->all())` and friends without `$fillable`/`$guarded`; lower severity when the flow is proven safe. |
| `LARAVEL_TAINT` | Error | high | Tainted variable interpolation into the query builder / `whereRaw`. |
| `INSECURE_COOKIE` | Error, Warning | high | Cookie flags: `Secure`/`HttpOnly`/`SameSite` missing, or `Secure` set to `false`. |
| `INSECURE_HASH` | Warning | high | Weak hashes (`md5()`, `sha1()`) used for passwords. |
| `SESSION_FIXATION` | Warning | medium | Session regenerated on login missing, or `session_regenerate(true)` skipped. |
| `WEAK_PASSWORD_POLICY` | Warning | medium | Weak `Password::defaults()` policy, or a password compared against a hardcoded literal (master-password pattern). |
| `DISABLED_CSRF_AUTHORIZE_TRUE` | Warning | high | `VerifyCsrfToken::except = ['*']` or `$except` covering every route. |
| `DISABLED_CSRF_EXCEPTION_STAR` | Warning | high | `withoutMiddleware(VerifyCsrfToken::class)` on a mutating route. |

Opt-in data-flow engine (`analyzers.security.taint_engine`, **off by default**):

| Rule ID | Severity | Confidence | What it detects |
|---|---|---|---|
| `TAINT_SQL_INJECTION` | Critical | high | Tainted value reaching a raw SQL sink. |
| `TAINT_COMMAND_INJECTION` | Critical | high | Tainted value reaching `exec`/`system`/`shell_exec`/`Process`. |
| `TAINT_EVAL` | Critical | high | Tainted value reaching `eval`/`assert`/dynamic `call_user_func`. |
| `TAINT_UNSAFE_SERIALIZE` | Error | high | Tainted value reaching `unserialize`. |

### OWASP (`analyzers/owasp`)

All 11 are on by default. Categories follow **OWASP Top 10 (2021)** — the
edition the mapping encodes. The 2025 revision reorders categories; rule ids and
category ids here are stable, so a category moves without renaming a rule.

| Rule ID | Severity | Confidence | OWASP 2021 | What it detects |
|---|---|---|---|---|
| `OWASP_BROKEN_ACCESS_CONTROL` | Error | medium | A01 | Mutating controller method (`store`/`update`/`delete`/...) with no visible `authorize`/`Gate`/`abort`/route middleware. |
| `OWASP_OWNERSHIP_IDOR` | Error | high, medium | A01 | Action reachable without an ownership check on the loaded record. Emits the decision chain as evidence (`PROTECTED` / `REVIEW` / `UNKNOWN`); see [docs/false-positives.md](docs/false-positives.md). |
| `OWASP_PATH_TRAVERSAL` | Error | high | A01 | User-controlled path segment reaching `include`/`require`/`file_get_contents`/`fopen`/`unlink`. |
| `OWASP_BLADE_DYNAMIC_INCLUDE` | Error | medium | A01 | Dynamic `@include`/`{!! !!}` target resolved from user input. |
| `OWASP_BLADE_XSS` | Error | high | A03 | Unescaped Blade output of a tainted value (`{!! !!}`, `raw()`, `@php echo`). |
| `OWASP_SSTI` | Error | high | A03 | Tainted data rendered as a template (`view()`, `Blade::render`). |
| `OWASP_COMMAND_INJECTION` | Critical | high | A03 | User input flowing into `system`/`exec`/`shell_exec`/`Process`. |
| `OWASP_MISCONFIGURATION` | Warning | high | A05 | Debug mode enabled, permissive CORS wildcard, placeholder or empty secrets (config files only). |
| `OWASP_XXE` | Error | high | A05 | `simplexml_load_*`/`DOMDocument`/`SimpleXMLElement` without an entity-loader guard. |
| `OWASP_OPEN_REDIRECT` | Error | high | A07 | Unvalidated redirect target from request input, including `header('Location: ...')` chains. |
| `OWASP_SSRF` | Error | high | A10 | User-controlled URL reaching `file_get_contents`/`fopen`/`Http::`/Guzzle. |

### Laravel (`analyzers/laravel`)

| Rule ID | Severity | Confidence | What it detects |
|---|---|---|---|
| `MIGRATION_MISSING_DOWN` | Warning | medium | Migration defines `up()` but no `down()` — not reversible. |
| `MIGRATION_DESTRUCTIVE_UP` | Warning | medium | Destructive schema operation (`dropTable`/`dropColumn`/...) in `up()` without re-creation. |
| `ROUTE_MISSING_VALIDATION` | Warning | medium | Mutating action with no `$request->validate()` and no FormRequest. |

### Test coverage (`analyzers/test_coverage`)

`test_coverage.unified` is on by default and emits the first five rules as
low-confidence hints. The last two are opt-in.

| Rule ID | Severity | Confidence | What it detects |
|---|---|---|---|
| `MISSING_CONTROLLER_TEST` | Info | low | Controller with no corresponding test (unit or feature). |
| `MISSING_SERVICE_TEST` | Info | low | Service with no corresponding test. |
| `MISSING_REPOSITORY_TEST` | Info | low | Repository with no corresponding test. |
| `MISSING_MODEL_TEST` | Info | low | Model with custom logic (>= 3 methods) but no test. |
| `MISSING_UNIT_TEST` | Info | low | Class in `app/` with neither a unit nor a feature test. |
| `MISSING_FEATURE_COVERAGE` | Info | high | Route declared with no feature test touching it (opt-in). |
| `TEST_WITHOUT_ASSERT` | Warning | low | Test method with no assertion (opt-in). |

### Convention (`analyzers/convention`, off by default)

| Rule ID | Severity | Confidence | What it detects |
|---|---|---|---|
| `LARAVEL_PITFALL_ENV_OUTSIDE_CONFIG` | Warning | medium | `env()` called outside `config/`. |
| `LARAVEL_PITFALL_DEBUG` | Warning | medium | Leftover `dd()`/`dump()`/`ray()` in shipped code. |
| `LARAVEL_PITFALL_SLEEP_IN_TEST` | Warning | medium | `sleep()`/`usleep()` in a test — hides flakiness instead of fixing it. |
| `DEAD_CODE` | Info | low | Methods/parameters never referenced (heuristic). |
| `NAMING_CONVENTION` | Info | low | Class/method/constant names that deviate from conventions. |
| `TODO_FIXME` | Info | low | Leftover `TODO` / `FIXME` / `HACK` markers. |

### Frontend (`analyzers/frontend`, on by default)

| Rule ID | Severity | Confidence | What it detects |
|---|---|---|---|
| `JS_SYNTAX_ERROR` | Warning | medium | Unbalanced `{}[]()` or unclosed string/template literal in `resources/js` / `public/js` (`.js`, `.jsx`, `.ts`, `.tsx`, `.vue` `<script>`). |
| `CSS_SYNTAX_ERROR` | Warning/Info | medium/low | Unbalanced `{}` or missing `;` before `}` in `resources/css` / `public/css` (`.css`, `.scss`, `.sass`, `.less`). |
| `BLADE_STACK_MISMATCH` | Error/Warning/Info | high/medium/low | `@push('x')` without `@stack('x')` (orphan, Warning), `@stack('x')` without `@push` (empty, Info), or `@push` without `@endpush` (Error) in `resources/views` `*.blade.php`. |

### Wrapped checkers

These are not rule ids — they are the third-party tools this package drives, and
their findings appear in reports under the `phpcs`, `phpstan`, `phpunit`,
`composer_audit` and `trivy` sources:

| Checker | What it gates |
|---|---|
| `phpcs` | PSR-12 (or your standard) violations; auto-fixable with `--fix`. |
| `phpstan` | Static type analysis at the configured level (default 5). |
| `phpunit` | Test suite result, plus the configured coverage threshold. |
| `composer_audit` | Known CVEs in the dependency tree. |
| `trivy` | Optional filesystem/config scan (off by default). |
### Confidence & Tiering

Every issue carries a **confidence**: `high` | `medium` | `low`.

- `high` → safe to gate CI (OWASP, taint, hardcoded secret, composer audit).
- `medium` → fairly reliable warning (`env()` outside config, `dd()` in app, insecure hash).
- `low` → heuristic hints, hidden unless you opt in (dead code, missing test, naming, todo).

Convention heuristics (`convention.*`) are **off by default** to avoid noise.
The unified test-coverage detector is enabled by default but emits low-confidence
warnings; raise `--min-confidence=high` or use the `security` tier when you want
to focus on security findings only.

### Severity

Every issue carries a severity, and `fail_on` decides which ones fail the build.

`OWASP_BLADE_DYNAMIC_INCLUDE` ships remapped to `info`. It reports every
dynamic view name — `@include($view)`, `@extends('a.' . $x)` — at `error`,
because Blade has no data-flow analysis and so cannot tell a user-steerable
template name from one built at runtime. Across a 27-project benchmark the Blade
findings were dominated by this rule, and at `error` a default run came out red
before the user had seen anything. At `info` it stays in the report without
failing a build. To treat every dynamic view name as blocking:

```php
// config/quality-checker.php
'analyzers' => [
    'severity_overrides' => [
        'OWASP_BLADE_DYNAMIC_INCLUDE' => 'error',
    ],
],
```

**`OWASP_BLADE_XSS` is not demoted**, and reflected XSS still fails the gate.
Its `error` severity fires only for request-derived output — `{!! request('q') !!}`
and the superglobals — which is reflected XSS and worth blocking. Its ordinary
`{!! $model->field !!}` hits are already `warning` and never turned a build red,
so demoting the whole rule would have cost that coverage without fixing the
noise.

Other rules can be remapped the same way. An unparseable severity is ignored
rather than guessed, so a typo cannot silently promote a rule to `error`.

The **tier** controls what the gate fails on:

| Tier | Fails on | Use for |
|---|---|---|
| `security` | high-confidence security issues only (OWASP/taint/secret) | security CI gate |
| `quality` | medium+ high error/critical (incl. phpcs/phpstan/phpunit) | standard CI gate (default) |
| `all` | same as `quality` today | local dev |

`quality` and `all` are currently identical; the distinct `all` behaviour is
planned, not shipped. Checkers that carry no quality-gate signal (dependency
audit, trivy, the heuristic analyzers) report the same in every tier — exclude
them with `exclude` in config or `--only` to keep them out of a gate run.

`--min-confidence` filters what is reported; `--tier` filters what the exit code fails on.

---

## Real-world benchmark

Custom analyzers only (phpcs/phpstan/phpunit excluded), `tier=security`,
`fail-on=none`, cold runs without cache. Quality is pinned by a labeled
corpus (`tests/Unit/AnalyzerMetricsTest.php`): **precision 1.000 / recall 1.000**
across 400 true/false-positive cases (240 TP + 160 TN) plus a 76-case holdout
(19% blind, never used for tuning) and a 30-injection recall suite (`tests/Unit/CveRecallTest.php` `30/30`), so the reductions below
cannot regress silently.

The table is a snapshot, not a live measurement — it records one day of output
by hand and no CI job re-measures it. To measure this tool on **your** projects,
use `tools/benchmark-projects.php` with a local manifest of paths (see the
header of that file for the format). It prints per-rule counts, prints each
rule's share of all findings, and `--diff=baseline.json` shows what moved after
an upgrade. Your manifest stays local; no project list ships with the package.

### External precision on your code (7/8)

Corpus precision is internal. For your codebase:

```bash
php -d memory_limit=1G bin/quality-check /path/to/project --only=custom --tier=security --fail-on=none --format=json --output=/tmp/out
php tools/sample-findings.php /tmp/out/quality-report.json --n=100 --seed=42 --out=sample.csv
# label sample.csv verdict column TP/FP, then per-rule precision = TP/(TP+FP) — target ≥0.85 for high rules
php tools/inter-rater.php reviewer1.csv reviewer2.csv  # kappa ≥0.9 for 8/10
# holdout is automatic: AnalyzerMetricsTest::holdoutCorpus() crc32(id)%5==0
```
| Target | Stack | Files | Before | After | Signal left |
|---|---|---|---|---|---|
| A — e-commerce monolith | Laravel 11 | 3,283 | 1,246 (7 / 466 / 773) | **1,077** (3 / 301 / 773) | 101 blade + public routes + Docs sample |
| B — internal HRM app | Laravel 12 | 526 | 191 (5 / 55 / 131) | **136** (1 / 6 / 129) | 4 open redirects + coverage |
| C — internal LMS app | Laravel 12 | ~600 | 176 (0 / 2 / 174) | **181** (0 / 7 / 174) | blade sanitized-display review |
| D — internal business app | Laravel | ~500 | 62 (0 / 1 / 61) | **66** (0 / 5 / 61) | 5 blade import-display |
| E — OSS wiki app | Laravel | ~1,400 | 186 (2 / 30 / 154) | **263** (2 / 109 / 152) | 75 redirect (16 high auth) + API auth |
| F — OSS PRM app (DDD) | Laravel | ~1,800 | 387 (3 / 7 / 377) | **386** (2 / 9 / 375) | 1 true `exec()` + validation debt |
| G — OSS e-commerce package | Laravel | ~200 | — | **2** (0 / 1 / 1) | JSON:API auth-in-core + coverage |
| H — OSS status-page app | Laravel | ~100 | — | **3** (0 / 0 / 3) | CORS wildcard + coverage |
| Dogfood — this package | PHP library | ~200 | 37 | **5** (3 / 1 / 1) | all intended (vuln fixtures + test secret) |
| Dogfood gate — this package `src/` | PHP library | 116 | — | **0** | clean; enforced by `.github/workflows/dogfood.yml` |
| I — internal POS edge app | Laravel | ~400 | — | **100** (0 / 55 / 45) | 39 blade + 10 unauth API review |
| J — internal POS cloud app | Laravel | ~500 | — | **182** (1 / 139 / 42) | 104 blade + 22 server-fetch review + 1 true open redirect |
| K — internal POS backend | Laravel | ~700 | — | **254** (1 / 50 / 203) | coverage debt + 20 BAC (JWT groups resolved) |
| L — internal web app (backend) | Laravel | ~600 | — | **511** (8 / 279 / 224) | hardcoded API key + exec-from-DB + 270 blade |
| M — internal web app (frontend) | Laravel | ~800 | — | **143** (1 / 46 / 96) | auth-flow findings + payment CSRF exceptions |
| N — OSS accounting app | Laravel | ~1,500 | — | **559** (1 / 523 / 35) | 500 blade + 3 unserialize TP + preg-guarded eval |
| O — OSS starter kit | Laravel | ~400 | — | **57** (0 / 16 / 41) | clean baseline |
| P — OSS ticketing app | Laravel | ~900 | — | **112** (0 / 57 / 55) | Form:: builders + installer CSRF |
| Q — OSS asset-mgmt app | Laravel | ~8,600 | — | **586** (6 / 291 / 289) | RSP-wrapped API auth + Storage temp URLs + dynamic-class call TP |
| R — OSS finance app | Laravel | ~1,700 | — | **473** (0 / 111 / 362) | amount formatters + Safe-URL redirects + FormRequest use-imports |
| S — OSS music app | Laravel | ~1,500 | — | **320** (12 / 16 / 292) | default-credential TP + presigned-URL redirects |
| T — OSS billing app | Laravel | ~4,100 | — | **654** (10 / 257 / 387) | seeder unguard + OAuth fixed-host redirects + FormRequest authorize |
| U — OSS admin package | Laravel | ~300 | — | **96** (17 / 49 / 30) | dynamic dispatch review + ternary-literal blade |
| V — OSS forum app | Laravel | ~450 | — | **53** (0 / 6 / 47) | assert/callable cleanup + markdown/excerpt renderers |
| W — OSS helpdesk app | Laravel | ~500 | — | **81** (4 / 42 / 35) | safe_raw_html + signed tracking links + module SSRF review |
| X — OSS blog package | Laravel | ~300 | — | **38** (1 / 6 / 31) | Gate-denies-throw + test fixtures + trivial authorize TP |
| Y — OSS link manager | Laravel | ~230 | — | **82** (0 / 54 / 28) | guarded install routes + login auth + plugin includes |
| Z — internal LMS app | Laravel 8 | ~200 | — | **195** (1 / 56 / 138) | master-password TP + session fixation + weak policy |
| AA — internal shop app | Laravel 8 | ~150 | — | **139** (0 / 24 / 115) | password policy + validation debt |
| AB — internal portal | Laravel 10 | ~450 | — | **265** (6 / 84 / 175) | shared master password + social login fixation |
| AC — internal warehouse app | Laravel | ~800 | — | **479** (22 / 196 / 261) | property-origin SSRF + leaked API key TP |

*(severity split: critical / error / warning)*

Biggest single win: `OWASP_BROKEN_ACCESS_CONTROL` on the e-commerce target (A) **453 → 150** —
actions protected by route middleware, `Route::controller()` groups and
cross-file `require` are now resolved; FQCN keys keep same-named Admin/Shop
controllers apart (see [docs/false-positives.md](docs/false-positives.md)).

Repeat runs are near-instant via the result cache (1 h TTL, keyed by file-set
hash + tool config **+ analyzer code version**, so package upgrades never
serve stale results).

---

## Auto-provisioning missing tools

Opt in to self-provisioning missing tools with `auto_install_tools => true` or
by dropping `--no-auto-install`:

- **phpcs / phpstan / phpunit** — installed via `composer require --dev` inside
  the target project when missing. This edits your `composer.json` and
  `vendor/`. It is off by default for that reason. (Slow on very large
  projects.)
- **trivy** — downloaded as a cached binary (GitHub releases) into a per-user
  cache directory, never touching the target project. Default version `0.74.0`
  (override with `trivy.version`). Binary is cached, so repeat runs are offline.
- If auto-install is off or fails, a checker uses a tool already available in the
  target project's `vendor/bin`; otherwise it is reported as `skipped` with an
  install hint.

---

## Troubleshooting

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

Run the custom analyzers and dependency audit without touching the project's
dependencies — the default, so the flag is only needed if you have opted in
globally:

```bash
php artisan quality:check --only=custom,composer_audit --no-auto-install
```

### A finding may be a heuristic false positive

Custom analyzers are static heuristics and do not replace a manual security
review. Check the file and line in the report, then use a reviewed baseline or
adjust the analyzer configuration rather than suppressing all security rules.
See [`docs/false-positives.md`](docs/false-positives.md) for a per-rule guide.

---

## Baseline Workflow

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

## Auto-fix

```bash
php artisan quality:check --fix
```

`--fix` runs `phpcbf` to auto-fix fixable coding-standard issues on the scanned
paths. If `phpcbf` is not installed, it prints a warning. Only coding-standard
issues are fixable; the custom analyzers are informational only.

---

## CI Integration (GitHub Actions)

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
          category: rampart-quality-checker
```

Severity mapping: `critical`/`error` → `error`, `warning` → `warning`,
`info` → `note`. Each rule is registered once with its highest observed
severity, and OWASP/taint/security rules are tagged accordingly.

### GitLab CI

```yaml
quality:
  stage: test
  image: php:8.3-cli
  before_script:
    - apt-get update && apt-get install -y git unzip
    - curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer
    - php -m | grep -q zip || docker-php-ext-install zip
    - composer install --prefer-dist --no-progress --no-interaction
  script:
    # Review without failing first; switch to the gated command once the
    # baseline is generated (see docs/baseline.md).
    - php artisan quality:check --ci --fail-on=none --output=reports/quality-checker
    - php artisan quality:check --ci
  artifacts:
    when: always
    paths: [reports/quality-checker]
    expire_in: 1 week
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
```

A `phpcs`/`phpstan`/`phpunit` run needs the dev dependencies; if you install with
`--no-dev`, add `--only=custom` to the gated command so the analyzer phase still
runs.

### Jenkins (Declarative Pipeline)

```groovy
pipeline {
    agent any
    environment {
        // Fail on the first finding above the threshold instead of collecting all of them.
        QUALITY_FAIL_ON = 'error'
    }
    stages {
        stage('Quality check') {
            steps {
                sh 'composer install --prefer-dist --no-progress --no-interaction'
                sh 'php artisan quality:check --format=all --output=reports/quality-checker'
            }
        }
    }
    post {
        always {
            archiveArtifacts artifacts: 'reports/quality-checker/*', allowEmptyArchive: true
            junit testResults: 'reports/quality-checker/*.xml', allowEmptyResults: true
        }
        unstable {
            // Exit code 1 = findings above the threshold. Treat the build as
            // unstable rather than failed so a red build is always a red build
            // for a real error, not for a finding.
            echo 'Quality gate not met: see reports/quality-checker/quality-report.html'
        }
    }
}
```

The HTML report is the artifact to link from the build page; it is
self-contained and needs no server.

### Azure Pipelines

```yaml
- task: UsePHP@2
  inputs:
    version: '8.3'
- script: composer install --prefer-dist --no-progress --no-interaction
  displayName: Install
- script: php artisan quality:check --format=all --output=reports/quality-checker
  displayName: Quality check
- task: PublishBuildArtifacts@1
  condition: always()
  inputs:
    PathtoPublish: reports/quality-checker
    ArtifactName: quality-report
```

---

## Pre-commit Hook

Pre-commit hook stubs are provided at `resources/stubs/pre-commit` and
`resources/stubs/pre-commit.ps1` (Unix and PowerShell respectively). Install the
relevant one into your project's `.git/hooks/` (or a hooks-manager like
[`pre-commit`](https://pre-commit.com)) to run the quality gate before every
commit.

---

## Developing & Testing the Package

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

### The package gates itself

`.github/workflows/dogfood.yml` runs on every push and pull request:

1. `composer check` — phpcs, phpstan level 6 and the full PHPUnit suite.
2. **Self-scan** — the package's own analyzers over its own shipped code:

   ```bash
   php bin/quality-check . --path=src --path=config --path=bin \
       --only=custom --fail-on=warning --no-cache
   ```

   `tests/` is out of scope there on purpose: it holds deliberately vulnerable
   analyzer samples, which are true positives. Everything else must be clean —
   findings in `src/` are either fixed or carry a written
   `// quality-checker-ignore-next-line` justification.

---

## Documentation

| Document | Read it when |
|---|---|
| [docs/index.md](docs/index.md) | You want the map of what exists and where the source of truth is. |
| [docs/baseline.md](docs/baseline.md) | Your first run reports hundreds of pre-existing findings. |
| [docs/false-positives.md](docs/false-positives.md) | A finding looks wrong, or you are choosing between fixing, suppressing and baselining. |
| [UPGRADE.md](UPGRADE.md) | You are moving between versions — **read before re-baselining**. |
| [SECURITY.md](SECURITY.md) | You found a vulnerability, or you run the gate on untrusted repositories. |
| [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) | You are contributing. |
| [CHANGELOG.md](CHANGELOG.md) | You want the full per-release history. |
| [CONTRIBUTING.md](CONTRIBUTING.md) | You are adding an analyzer or opening a pull request. |
| [SPEC.md](SPEC.md) | You want the original design document and the contracts it fixed. |

The rule tables above are parsed by `tests/Unit/RuleDocsTest.php`, which fails
if the docs and `src/Result/RuleIds.php` disagree — a rule cannot ship
undocumented, and a documented id cannot be one the analyzers never emit.

---

## License

[MIT](LICENSE) © 2026 Rampart
