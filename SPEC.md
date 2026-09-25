# Laravel Quality Checker — Plan & Technical Specification

> Version: 0.1 (draft)
> Goal: A Laravel package running as a CLI (Artisan) for comprehensive code quality checks,
> covering coding standard, static analysis, unit test, missing test cases, security, convention.
> It wraps available CLI tools + adds custom rules written with PHP-Parser for Security/Testcase/Convention.

---

## 1. Overview

### 1.1 Problem to solve
- Code quality across Laravel projects is often inconsistent.
- Developers have to remember to run many separate tools: `phpcs`, `phpstan`, `phpunit`, `composer audit`, `trivy`, ...
- There is no mechanism to detect **missing test cases** or **security holes per team convention**.
- There is no unified report for CI integration.

### 1.2 Solution
A Laravel package (`vietvang/quality-checker`) providing an Artisan command:

```
php artisan quality:check
```

Combines all tools into **a single command**, returning a **console table**, **JSON**, **HTML**, **Markdown**, and a CI-ready **exit code**.

### 1.3 Design principles
| Principle | Description |
|---|---|
| **Wrap, don't rewrite** | Standard tools (phpcs/phpstan/phpunit/audit/trivy) are invoked via CLI, only their output is parsed. |
| **Write custom code only when needed** | PHP-Parser is only used where no tool exists yet: security heuristics, missing test cases, convention. |
| **Zero-config by default** | Works right after installation, with config to extend/disable rules. |
| **CI-friendly** | Non-zero exit code on errors, machine-readable JSON. |
| **Extensible** | Plugin/rule architecture allows adding new rules without touching core. |

---

## 2. Package architecture

### 2.1 Directory structure

```
laravel-quality-checker/
├── composer.json
├── LICENSE
├── README.md
├── config/
│   └── quality-checker.php          # config published into the project
├── src/
│   ├── QualityCheckerServiceProvider.php
│   ├── Commands/
│   │   └── QualityCheckCommand.php   # php artisan quality:check
│   ├── Checkers/
│   │   ├── CheckerInterface.php      # shared contract for all checkers
│   │   ├── AbstractProcessChecker.php # runs a CLI tool, parses exit code + output
│   │   ├── PhpcsChecker.php
│   │   ├── PhpstanChecker.php
│   │   ├── PhpunitChecker.php
│   │   ├── ComposerAuditChecker.php
│   │   ├── TrivyChecker.php
│   │   └── CustomAnalyzerChecker.php  # runs custom analyzers (PHP-Parser)
│   ├── Analyzers/                    # custom rules (written with PHP-Parser)
│   │   ├── AbstractAnalyzer.php
│   │   ├── Security/
│   │   │   ├── SqlInjectionAnalyzer.php
│   │   │   ├── UnsafeEvalAnalyzer.php
│   │   │   ├── HardcodedSecretAnalyzer.php
│   │   │   ├── MassAssignmentAnalyzer.php
│   │   │   ├── UnsafeDeserializationAnalyzer.php
│   │   │   └── LaravelTaintAnalyzer.php
│   │   ├── TestCoverage/
│   │   │   ├── MissingTestAnalyzer.php
│   │   │   ├── ControllerTestAnalyzer.php
│   │   │   └── FeatureTestAnalyzer.php
│   │   └── Convention/
│   │       ├── NamingConventionAnalyzer.php
│   │       ├── TodoFixmeAnalyzer.php
│   │       ├── DeadCodeAnalyzer.php
│   │       └── LaravelPitfallAnalyzer.php
│   ├── Reporters/
│   │   ├── ReporterInterface.php
│   │   ├── ConsoleReporter.php        # terminal table (Symfony Table)
│   │   ├── JsonReporter.php
│   │   ├── HtmlReporter.php
│   │   └── MarkdownReporter.php
│   ├── Runner/
│   │   ├── CheckRunner.php            # orchestrator: runs checkers, collects results, exit code
│   │   └── CheckContext.php           # DTO: path, config, options, autoload
│   ├── Result/
│   │   ├── CheckResult.php            # result of 1 checker (status, issues, duration, raw)
│   │   ├── Issue.php                  # 1 issue (file, line, severity, rule, message)
│   │   └── Severity.php               # enum: info | warning | error | critical
│   └── Exceptions/
│       └── ToolNotFoundException.php  # tool not installed
├── tests/                            # unit + integration tests for the package
└── stubs/                            # published config and hook stubs
```

### 2.2 Processing flow

```
php artisan quality:check [--format=...] [--only=...] [--exclude=...] [--fail-on=...]
        │
        ▼
QualityCheckCommand ──► config/quality-checker.php (load package/project config)
        │
        ▼
CheckRunner.buildCheckers(config, options)
        │
        ├─► PhpcsChecker ──► exec("vendor/bin/phpcs ...")  ──► parse XML/JSON
        ├─► PhpstanChecker ──► exec("vendor/bin/phpstan analyse ...")
        ├─► PhpunitChecker ──► exec("vendor/bin/phpunit --log-junit ...")
        ├─► ComposerAuditChecker ──► exec("composer audit ...")
        ├─► TrivyChecker ──► exec("trivy fs ...")
        └─► CustomAnalyzerChecker ──► PHP-Parser parse codebase
                    │
                    ▼
            Collect CheckResult[] (1 CheckResult per checker, containing Issue[])
        │
        ▼
Reporter.render(results, format)
        │
        ├─ ConsoleReporter  → Symfony table (console)
        ├─ JsonReporter     → quality-report.json
        ├─ HtmlReporter     → quality-report.html
        └─ MarkdownReporter → quality-report.md
        │
        ▼
exit(code)  // 0 = pass, >0 = issues exceed --fail-on
```

---

## 3. Contract & Data model

### 3.1 `CheckerInterface`

```php
interface CheckerInterface
{
    public function name(): string;            // "phpcs"
    public function description(): string;
    public function isAvailable(CheckContext $ctx): bool;  // does the tool exist?
    public function run(CheckContext $ctx): CheckResult;
    public function config(): array;           // checker's own config section
}
```

### 3.2 `CheckResult`

```php
final class CheckResult
{
    public string $name;
    public string $status;     // 'passed' | 'warning' | 'failed' | 'skipped' | 'error'
    public float $duration;    // seconds
    public array $issues;      // Issue[]
    public ?string $rawOutput; // raw tool output (for debugging)
    public ?string $summary;   // "12 errors in 5 files"
}
```

### 3.3 `Issue`

```php
final class Issue
{
    public string $rule;       // 'SQL_INJECTION' | 'PHPCBF_...' | 'PHPSTAN_...'
    public string $message;
    public ?string $file;
    public ?int $line;
    public Severity $severity; // info | warning | error | critical
    public string $source;     // 'phpcs' | 'phpstan' | 'phpunit' | 'custom'
    public array $metadata;    // extra: fixable?, link, tool internal id...
}
```

### 3.4 `Severity`
- `info` — hint, does not affect exit code.
- `warning` — warning (depends on `--fail-on`).
- `error` — serious error (fails by default).
- `critical` — security/dangerous (always fails unless disabled).

---

## 4. Checkers — wrapping CLI tools

### 4.1 PHPCS (PHP_CodeSniffer)
- Command: `vendor/bin/phpcs --standard={config} --report=json {paths}`
- Parse: JSON report → map `files[].messages[]` → `Issue`.
- Config:
  - `standard`: defaults to `PSR-12`, reads the project's `phpcs.xml` if present.
  - `paths`: defaults to `app/ routes/ config/ database/ tests/`.
  - `severityThreshold`, `excludeSniffs`.

### 4.2 PHPStan
- Command: `vendor/bin/phpstan analyse {paths} --level={level} --error-format=json --no-progress`
- Parse: JSON → `files[].messages[]` (tip, message, line).
- Config: `level` (default 5), `paths`, `memoryLimit`.

### 4.3 PHPUnit
- Command: `vendor/bin/phpunit --testsuite=... --log-junit=tmp/phpunit.xml`
- Parse: JUnit XML → test, failure, error, skipped counts; turns failures into `Issue` (error severity).
- Config: `testsuite`, `coverageThreshold` (with Xdebug/PCOV — see §6).

### 4.4 Composer Audit (security dependencies)
- Command: `composer audit --format=json`
- Parse: `advisories` → `Issue` with critical/error severity according to the advisory `severity`.
- No extra tool installation needed; built into Composer 2.4+.

### 4.5 Trivy (optional — scan filesystem)
- Command: `trivy fs --format json {path}` or `trivy config` (scans IaC config, secrets).
- Parse: `Results[].Target` + `Vulnerabilities[]` → `Issue` (misconfig/secret part only).
- Disabled by default if trivy is not installed → `skipped` status with an installation hint.

### 4.6 Common handling when a tool is missing
- `isAvailable()` checks the binary/autoload.
- If missing → `skipped` + suggested install command (`composer require --dev phpstan/phpstan`, etc.).

---

## 5. Custom Analyzers (written with PHP-Parser)

This is the "core" of the package — AST analysis of the codebase.

### 5.1 Infrastructure
- Uses `nikic/php-parser` (bundled with the package or required via composer).
- `AbstractAnalyzer`:
  - `analyze(array $files): array` — returns `Issue[]`.
  - `supports(string $path): bool` — only accepts `.php`.
  - `analyzeFile(string $file, Node $ast): Issue[]`.
- `CustomAnalyzerChecker`:
  - Walks all of `app/ routes/ database/` (configurable).
  - Each file is parsed with `ParserFactory` (emitting `PhpVersion` per composer.json).
  - Runs each enabled analyzer, collects `Issue[]`, sets `source = 'custom'`.

### 5.2 Security Analyzers (severity: error/critical)

| Rule ID | Description | Detection example |
|---|---|---|
| `SQL_INJECTION` | Detects tainted input flowing into raw queries | `DB::select("SELECT * FROM t WHERE x = " . $request->input('x'))`, `whereRaw()` with request-derived variables |
| `UNSAFE_EVAL` | `eval()`, `assert()` with dynamic data | `eval($userInput);` |
| `HARDCODED_SECRET` | Hardcoded secrets/API keys in code | `'api_key' => 'sk-12345'`, regexes catching `sk-`, `AIza`, `AKIA`, `-----BEGIN PRIVATE KEY` |
| `MASS_ASSIGNMENT` | `Model::create($request->all())` without `$fillable`/`$guarded` | `User::create($request->all());` |
| `UNSAFE_UNSERIALIZE` | `unserialize()` on untrusted data | `unserialize($cookie);` |
| `INSECURE_HASH` | Weak hashing | `md5()`, `sha1()` used for passwords |
| `LARAVEL_TAINT` | Tainted interpolated variables flowing into query builder/`whereRaw` | `->whereRaw("price > $min")` |
| `DISABLED_CSRF` | `@csrf`/`VerifyCsrfToken` skipped | `web` route without CSRF middleware |

> Taint tracking: v1 uses **pattern-based heuristics** (AST match) first; v2 may upgrade to data-flow taint (provenance map across calls) — see Roadmap.

### 5.3 Missing Testcase Analyzers (severity: warning)

| Rule ID | Description | Logic |
|---|---|---|
| `MISSING_CONTROLLER_TEST` | Controller in `app/Http/Controllers/` without a matching test | `app/.../UserController.php` ↔ `tests/Feature/UserControllerTest.php` or `tests/Feature/Controllers/UserControllerTest.php` |
| `MISSING_SERVICE_TEST` | Service/Repository in `app/Services/`, `app/Repositories/` without a test | 1:1 mapping to `tests/Unit/...` |
| `MISSING_MODEL_TEST` | Model with complex logic (custom methods, scopes, casts) without a test | scans method count + finds the matching test file |
| `MISSING_FEATURE_COVERAGE` | Route/endpoint no feature test touches | parses `routes/`, matches action names against test methods (heuristic, v1) |
| `TEST_WITHOUT_ASSERT` | Test method exists but has no assertion | test method AST contains no `assert*`, `expects*` |
| `LOW_TEST_RATIO` | Test-to-source ratio below threshold | config `minRatio` (default 0.3) |

> Test ↔ source file mapping: uses directory conventions + class names (stripping prefix, `Controller`/`Service`/... suffixes). Results are warnings, CI does not fail by default.

### 5.4 Convention Analyzers (severity: info/warning)

| Rule ID | Description | Example |
|---|---|---|
| `NAMING_CONVENTION` | Class/method/const names violating conventions | controller without `Controller` suffix, action method not starting with `is/has/get/set`... |
| `TODO_FIXME` | Leftover TODO/FIXME/HACK in code | `// TODO: fix later` |
| `DEAD_CODE` | Unused method/param (heuristic) | `public function helper()` never called in the whole codebase |
| `LARAVEL_PITFALL` | Laravel anti-patterns | `DB::raw` outside migrations, queries in views, `env()` outside config, leftover `dd()`/`dump()` in production code, sleep in tests |

---

## 6. Test coverage (ratio & threshold)

- Only runs with `phpunit --coverage-*` (requires active `xdebug`/`pcov`) — reads JUnit XML containing coverage if configured.
- Without a coverage extension → this checker is `skipped` + hint.
- Config: `phpunit.coverageThreshold` (default 60% line coverage) → below the threshold creates an `Issue` (warning).

---

## 7. Reporters

### 7.1 Interface

```php
interface ReporterInterface
{
    public function render(array $results, CheckContext $ctx): void;
}
```

### 7.2 Reporter details

| Reporter | Output | Used for |
|---|---|---|
| `ConsoleReporter` | Summary table (Symfony Table): checker name, status, issue count, duration, total score | Manual dev runs |
| `JsonReporter` | `quality-report.json`: `{ generated_at, version, exit_code, summary, checkers: [ ... ] }` | CI/machine |
| `HtmlReporter` | `quality-report.html` (Blade template + inline CSS, single self-contained file) | Share/archive |
| `MarkdownReporter` | `quality-report.md` (table + issue list per file) | Docs/PR comment |

### 7.3 JSON schema (excerpt)

```json
{
  "generated_at": "2026-09-20T10:00:00+07:00",
  "package_version": "1.0.0",
  "exit_code": 1,
  "summary": { "checkers": 7, "passed": 3, "failed": 2, "skipped": 2, "total_issues": 18, "critical": 1 },
  "checkers": [
    {
      "name": "phpcs",
      "status": "failed",
      "duration": 2.41,
      "issues": [
        { "rule": "PSR12.Files.FileHeader.SpacingAfterBlock", "severity": "error",
          "file": "app/Http/Controllers/UserController.php", "line": 12,
          "message": "There must be exactly one blank line after the file header" }
      ]
    }
  ]
}
```

---

## 8. Artisan command — CLI

### 8.1 Command

```
php artisan quality:check [options]
```

### 8.2 Options

| Option | Description | Default |
|---|---|---|
| `--format=...` | `console` (default), or `console,json,html,md` separated by `,` to run several | `console` |
| `--only=...` | Only run the specified checkers, e.g. `phpcs,phpstan,custom` | all |
| `--exclude=...` | Skip checkers | — |
| `--path=...` | Override scan paths | config |
| `--fail-on=severity` | Fail threshold: `warning` | `error` | `critical` | `none` | `error` |
| `--output=...` | Report output directory (defaults to `reports/quality-checker/`) | as above |
| `--no-cache` | Skip analyzer result cache | — |
| `--quiet` | Print summary only | — |
| `--json` | Equivalent to `--format=json` (shortcut) | — |
| `--ci` | CI mode: defaults to `--format=json`, `--fail-on=error`, `--no-progress` | — |

### 8.3 Exit code

| Code | Meaning |
|---|---|
| `0` | Pass (no issue exceeds the `--fail-on` threshold) |
| `1` | Has issues exceeding the threshold (`error` and above by default) |
| `2` | Environment error (missing tool, bad config) |
| `3` | Runtime error of the package itself |

---

## 8.5 Auto-provisioning missing tools

When a checker cannot find its tool, the package **resolves it automatically** instead of just reporting `skipped`:

| Tool | Auto-install mechanism |
|---|---|
| `phpcs` / `phpstan` / `phpunit` | `composer require --dev <package>` in the target project (via `ToolInstaller`). |
| `trivy` | Downloads the binary from GitHub releases (`TrivyDownloader`) into the per-user cache `~/.quality-checker/trivy`, without touching the project. |

Priority order when a tool is missing:
1. **Auto-install** (if `auto_install_tools=true` and no `--no-auto-install`).
2. **Fallback vendor package** — uses the tool already in the package's own `vendor/bin`.
3. If still missing → `skipped` with the **exact manual install command** (no more generic message).

Decisions:
- `--no-auto-install` / `auto_install_tools => false` disables it (air-gapped/read-only projects).
- Default Trivy version is `0.74.0`, configured via `trivy.version`.
- `composer audit` runs with `--no-interaction`, 120s timeout, reports `error` (not `passed`) when the command itself fails (offline/rate-limit).

---

## 9. Config (publish)

```php
// config/quality-checker.php
return [
    'paths' => ['app', 'routes', 'database', 'config', 'tests'], // default scan paths
    'exclude' => [],

    // Auto-install missing tools: phpcs/phpstan/phpunit via composer, trivy via cached binary.
    'auto_install_tools' => true,

    // Quality gate: security | quality | all.
    'tier' => 'quality',

    // Minimum confidence threshold to display: low | medium | high.
    'min_confidence' => 'low',

    'phpcs'   => ['standard' => 'PSR12', 'severity' => 0],
    'phpstan' => ['level' => 5, 'memoryLimit' => '1G'],
    'phpunit' => ['testsuite' => null, 'coverageThreshold' => 60],
    'composer_audit' => ['enabled' => true],
    'trivy'   => ['enabled' => false, 'mode' => 'config', 'binary' => 'trivy', 'version' => '0.74.0'],

    'analyzers' => [
        'enabled' => true,
        'security' => [
            'sql_injection' => true,
            'unsafe_eval' => true,
            'hardcoded_secret' => true,
            'mass_assignment' => true,
            'unsafe_unserialize' => true,
            'insecure_hash' => true,
            'laravel_taint' => true,
            'disabled_csrf' => true,
            'taint_engine' => false,
        ],
        'owasp' => [
            'broken_access_control' => true,
            'ssrf' => true,
            'ssti' => true,
            'misconfiguration' => true,
            'command_injection' => true,
            'xxe' => true,
        ],
        'laravel' => [
            'migration' => true,
            'route_validation' => true,
        ],
        'test_coverage' => [ // heuristic, OFF by default
            'missing_controller_test' => false,
            'missing_service_test' => false,
            'missing_model_test' => false,
            'missing_feature_coverage' => false,
            'test_without_assert' => false,
        ],
        'convention' => [ // heuristic, OFF by default
            'naming_convention' => false,
            'todo_fixme' => false,
            'dead_code' => false,
            'laravel_pitfall' => false,
        ],
    ],

    'fail_on' => 'error',
    'output_dir' => 'reports/quality-checker',
];
```

- Publish: `php artisan vendor:publish --tag=quality-checker-config`.

---

## 10. CI integration (example)

```yaml
# .github/workflows/quality.yml
- name: Quality Check
  run: php artisan quality:check --ci
  env:
    PHP_VERSION: 8.2
- name: Upload report
  uses: actions/upload-artifact@v4
  with:
    path: reports/quality-checker/quality-report.json
```

---

## 11. Roadmap

### Phase 1 — MVP (month 1)
- [x] Package structure + ServiceProvider + `quality:check` command.
- [x] `PhpcsChecker`, `PhpstanChecker`, `PhpunitChecker`, `ComposerAuditChecker`.
- [x] `ConsoleReporter` + `JsonReporter`.
- [x] Exit code + `--only/--exclude/--fail-on`.
- [x] First 3 security analyzers (SQL injection, eval, hardcoded secret).
- [x] Basic `MissingTestAnalyzer`.
- [ ] Unit tests for the package, package CI.

### Phase 2 — Expansion (month 2)
- [ ] `HtmlReporter` + `MarkdownReporter` (Blade).
- [ ] `TrivyChecker`.
- [ ] All security + convention analyzers.
- [ ] Result cache (`--no-cache`), parallel runner (multi-process).
- [ ] `--ci` mode, threshold config, coverage from PHPUnit.

### Phase 3 — Advanced (month 3)
- [ ] Real taint data-flow (provenance map via call graph).
- [ ] Baseline (record known issues to only report new issues).
- [ ] `--fix` interface for auto-fixable errors (delegating to phpcs fixer, php-cs-fixer).
- [ ] Hooks: pre-commit script, IDE plugins (PHPStorm/VS Code) embedding reports.

---

## 12. Risks & notes

| Risk | Mitigation |
|---|---|
| Tool not installed in the project | `isAvailable()` + `skipped` status + install command hint |
| Tool output changes between versions | Pin to official JSON schemas (phpcs `--report=json`, phpstan `--error-format=json`), standard JUnit XML |
| Analyzer false positives | Each rule has its own `--only/--exclude`, low severity for heuristics, baseline in Phase 3 |
| Perf when scanning large codebases | Lazy per-file parsing, AST cache, parallel in Phase 2 |
| Incompatible PHP version | `ParserFactory::createForNewestSupportedVersion()` + fallback per composer.json |

---

## 13. To confirm before coding

1. **Package name / vendor namespace** — e.g. `vietvang/quality-checker`?
2. **Minimum supported PHP version** (8.1 / 8.2 / 8.3)?
3. **Supported Laravel version range** (10 / 11 / 12)?
4. **Default threshold** for `fail_on` (error or warning)?
5. Is **baseline** (skipping old issues) needed from the start?
6. Is **`--fix`** (phpcs auto-fix) wanted in the MVP?

---

## 14. Confidence model & Tiering (noise reduction)

Problem: heuristic analyzers (dead code, missing test, naming, todo) generate thousands of
info/warning items drowning out a few real security findings. Solution:

### 14.1 Confidence
Each `Issue` carries `confidence: high | medium | low` (enum `Confidence`, order 3>2>1).

| Confidence | Meaning | Example |
|---|---|---|
| **high** | Certain, may fail CI | OWASP, taint dataflow, hardcoded secret, SQL injection, composer audit |
| **medium** | Fairly certain, warning | `env()` outside config, `dd()` in app, insecure hash |
| **low** | Heuristic hint, hidden by default | dead code, missing test, naming, todo/fixme |

- `--min-confidence=low|medium|high` filters issues by threshold (default `low` = show all).
- `CheckRunner::shouldFail()` only fails when an issue is ≥ `min_confidence` and ≥ `fail_on` severity.

### 14.2 Tier (quality gate)
`--tier=security|quality|all` (default `quality`, from config `tier`).

| Tier | Fails when | Used for |
|---|---|---|
| `security` | Only high-confidence security issues (OWASP/taint/secret/composer_audit) | Security CI gate |
| `quality` | high+medium error/critical (including phpcs/phpstan/phpunit) | Quality CI gate (default) |
| `all` | Everything (including heuristics if enabled) | Manual dev runs |

In the `security` tier, `shouldFail()` ignores non-`composer_audit` issues with
confidence < high (i.e. it only fails on certain security findings).

### 14.3 Heuristics OFF by default
`analyzers.test_coverage.*` and `analyzers.convention.*` default to `false` (opt-in).
Only security + owasp + tool checkers are enabled out of the box → concise output, less noise.

### 14.4 Deduplicator
`src/Analyzers/Deduplicator.php` — merges duplicate issues by signature `md5(rule|file|line|message)`,
keeping the highest-confidence one. Resolves overlap between `LaravelTaintAnalyzer` (heuristic)
and `TaintEngine` (dataflow).

---

## 15. OWASP Top 10 (2023) API mapping

Module `src/Analyzers/Owasp/`, rule prefix `OWASP_`, confidence **high**.

| Rule ID | Severity | OWASP | Analyzer |
|---|---|---|---|
| `OWASP_BROKEN_ACCESS_CONTROL` | Error | A01 Broken Access Control | `OwaspAccessControlAnalyzer` |
| `OWASP_SSRF` | Error | A10 Server-Side Request Forgery | `OwaspSsrfAnalyzer` |
| `OWASP_SSTI` | Error | A03 Injection (SSTI) | `OwaspSstiAnalyzer` |
| `OWASP_MISCONFIGURATION` | Warning | A05 Security Misconfiguration | `OwaspMisconfigurationAnalyzer` |
| `OWASP_COMMAND_INJECTION` | Critical | A03 Injection (Command) | `OwaspCommandInjectionAnalyzer` |
| `OWASP_XXE` | Error | A05 XML External Entity | `OwaspXxeAnalyzer` |

Config: `analyzers.owasp.{rule}` (default `true`). Reports add an OWASP section:
- JSON: key `owasp` = `{ categories: {A01...: n}, total }`.
- Console/Markdown/HTML: OWASP table per rule when there are `OWASP_*` issues.

### Detection summary
| Analyzer | Detected sink | Conservative rule |
|---|---|---|
| AccessControl | Mutating controller method (store/update/delete/... or calling save/delete/update/create) **without** authorize/Gate/abort/middleware | Mutating methods only, skipping magic/`__*` |
| SSRF | `file_get_contents/fopen/curl/Http::*/Guzzle` with non-literal URL | Non-literal URLs only |
| SSTI | `Blade::render/compileString`, `view()->render()` with non-literal template | Non-literal only |
| Misconfiguration | `'debug'=>true`, `APP_DEBUG=true`, CORS `*`, secret placeholder | Specific matches only, no header inference |
| CommandInjection | `system/exec/shell_exec/passthru/proc_open/popen/Process` + input | Uses `isTaintedExpr` |
| XXE | `simplexml_load_*/DOMDocument/SimpleXMLElement/XMLReader` without a `libxml_disable_entity_loader` guard | Skips files with a guard |
