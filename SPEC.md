# Laravel Quality Checker — Plan & Technical Specification

> Version: 0.1 (draft)
> Mục tiêu: Package Laravel chạy dạng CLI (Artisan) để kiểm tra chất lượng code toàn diện,
> gồm coding standard, static analysis, unit test, thiếu test case, security, convention.
> Bọc các tool CLI có sẵn + tự viết rule bằng PHP-Parser cho phần Security/Testcase/Convention.

---

## 1. Tổng quan

### 1.1 Vấn đề cần giải quyết
- Code quality của các dự án Laravel thường không đồng nhất.
- Nhà phát triển phải nhớ chạy nhiều tool rời rạc: `phpcs`, `phpstan`, `phpunit`, `composer audit`, `trivy`, ...
- Không có cơ chế phát hiện **thiếu test case** hay **lỗ hổng bảo mật theo convention của team**.
- Không có báo cáo thống nhất để tích hợp CI.

### 1.2 Giải pháp
Một package Laravel (`vietvang/quality-checker`) cung cấp lệnh Artisan:

```
php artisan quality:check
```

Gộp tất cả công cụ thành **một lệnh duy nhất**, trả về **bảng console**, **JSON**, **HTML**, **Markdown**, và **exit code** chuẩn cho CI.

### 1.3 Nguyên tắc thiết kế
| Nguyên tắc | Mô tả |
|---|---|
| **Wrap, không rewrite** | Các tool chuẩn (phpcs/phpstan/phpunit/audit/trivy) được gọi qua CLI, chỉ parse output. |
| **Tự viết chỉ khi cần** | PHP-Parser chỉ dùng cho phần chưa có tool sẵn: security heuristics, thiếu testcase, convention. |
| **Zero-config mặc định** | Chạy được ngay sau khi cài, có cấu hình để mở rộng/tắt rule. |
| **CI-friendly** | Exit code không-zero khi có lỗi, JSON machine-readable. |
| **Extensible** | Kiến trúc plugin/rule cho phép thêm rule mới không cần sửa core. |

---

## 2. Kiến trúc package

### 2.1 Cấu trúc thư mục

```
laravel-quality-checker/
├── composer.json
├── LICENSE
├── README.md
├── config/
│   └── quality-checker.php          # config publish vào project
├── src/
│   ├── QualityCheckerServiceProvider.php
│   ├── Commands/
│   │   └── QualityCheckCommand.php   # php artisan quality:check
│   ├── Checkers/
│   │   ├── CheckerInterface.php      # contract chung cho mọi checker
│   │   ├── AbstractProcessChecker.php # chạy tool CLI, parse exit code + output
│   │   ├── PhpcsChecker.php
│   │   ├── PhpstanChecker.php
│   │   ├── PhpunitChecker.php
│   │   ├── ComposerAuditChecker.php
│   │   ├── TrivyChecker.php
│   │   └── CustomAnalyzerChecker.php  # chạy các custom analyzer (PHP-Parser)
│   ├── Analyzers/                    # custom rules (tự viết bằng PHP-Parser)
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
│   │   ├── ConsoleReporter.php        # bảng trong terminal (Symfony Table)
│   │   ├── JsonReporter.php
│   │   ├── HtmlReporter.php
│   │   └── MarkdownReporter.php
│   ├── Runner/
│   │   ├── CheckRunner.php            # orchestrator: chạy checker, thu kết quả, exit code
│   │   └── CheckContext.php           # DTO: path, config, options, autoload
│   ├── Result/
│   │   ├── CheckResult.php            # kết quả 1 checker (status, issues, duration, raw)
│   │   ├── Issue.php                  # 1 vấn đề (file, line, severity, rule, message)
│   │   └── Severity.php               # enum: info | warning | error | critical
│   └── Exceptions/
│       └── ToolNotFoundException.php  # tool chưa cài
├── tests/                            # unit + integration test cho package
└── stubs/                            # published config and hook stubs
```

### 2.2 Luồng xử lý

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
            Collect CheckResult[] (mỗi checker 1 CheckResult, chứa Issue[])
        │
        ▼
Reporter.render(results, format)
        │
        ├─ ConsoleReporter  → bảng Symfony (console)
        ├─ JsonReporter     → quality-report.json
        ├─ HtmlReporter     → quality-report.html
        └─ MarkdownReporter → quality-report.md
        │
        ▼
exit(code)  // 0 = pass, >0 = có lỗi theo --fail-on
```

---

## 3. Contract & Data model

### 3.1 `CheckerInterface`

```php
interface CheckerInterface
{
    public function name(): string;            // "phpcs"
    public function description(): string;
    public function isAvailable(CheckContext $ctx): bool;  // tool tồn tại?
    public function run(CheckContext $ctx): CheckResult;
    public function config(): array;           // phần config riêng của checker
}
```

### 3.2 `CheckResult`

```php
final class CheckResult
{
    public string $name;
    public string $status;     // 'passed' | 'warning' | 'failed' | 'skipped' | 'error'
    public float $duration;    // giây
    public array $issues;      // Issue[]
    public ?string $rawOutput; // output thô của tool (để debug)
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
- `info` — gợi ý, không ảnh hưởng exit code.
- `warning` — cảnh báo (tùy `--fail-on`).
- `error` — lỗi nghiêm trọng (mặc định fail).
- `critical` — bảo mật/nguy hiểm (luôn fail trừ khi tắt).

---

## 4. Các Checker — wrap tool CLI

### 4.1 PHPCS (PHP_CodeSniffer)
- Lệnh: `vendor/bin/phpcs --standard={config} --report=json {paths}`
- Parse: JSON report → map `files[].messages[]` → `Issue`.
- Cấu hình:
  - `standard`: mặc định `PSR-12`, đọc `phpcs.xml` của project nếu có.
  - `paths`: mặc định `app/ routes/ config/ database/ tests/`.
  - `severityThreshold`, `excludeSniffs`.

### 4.2 PHPStan
- Lệnh: `vendor/bin/phpstan analyse {paths} --level={level} --error-format=json --no-progress`
- Parse: JSON → `files[].messages[]` (tip, message, line).
- Cấu hình: `level` (mặc định 5), `paths`, `memoryLimit`.

### 4.3 PHPUnit
- Lệnh: `vendor/bin/phpunit --testsuite=... --log-junit=tmp/phpunit.xml`
- Parse: JUnit XML → số tests, failures, errors, skipped; đưa failure thành `Issue` (severity error).
- Cấu hình: `testsuite`, `coverageThreshold` (nếu dùng Xdebug/PCOV — xem §6).

### 4.4 Composer Audit (security dependencies)
- Lệnh: `composer audit --format=json`
- Parse: `advisories` → `Issue` severity critical/error theo `severity` của advisory.
- Không cần cài thêm tool; có sẵn trong Composer 2.4+.

### 4.5 Trivy (optional — scan filesystem)
- Lệnh: `trivy fs --format json {path}` hoặc `trivy config` (scan IaC config, secret).
- Parse: `Results[].Target` + `Vulnerabilities[]` → `Issue` (riêng phần misconfig/secret).
- Mặc định **disabled** nếu chưa cài trivy → status `skipped` với hint cài đặt.

### 4.6 Xử lý chung khi tool chưa cài
- `isAvailable()` kiểm tra binary/autoload.
- Nếu thiếu → `skipped` + gợi ý lệnh cài (`composer require --dev phpstan/phpstan`, v.v.).

---

## 5. Custom Analyzers (tự viết bằng PHP-Parser)

Phần này là "ruột" của package — phân tích AST của codebase.

### 5.1 Infrastructure
- Dùng `nikic/php-parser` (bundle vào package hoặc yêu cầu qua composer).
- `AbstractAnalyzer`:
  - `analyze(array $files): array` — trả về `Issue[]`.
  - `supports(string $path): bool` — chỉ nhận `.php`.
  - `analyzeFile(string $file, Node $ast): Issue[]`.
- `CustomAnalyzerChecker`:
  - Walk toàn bộ `app/ routes/ database/` (cấu hình được).
  - Mỗi file parse bằng `ParserFactory` (emit `PhpVersion` theo composer.json).
  - Chạy từng analyzer đang bật, gom `Issue[]`, set `source = 'custom'`.

### 5.2 Security Analyzers (severity: error/critical)

| Rule ID | Mô tả | Ví dụ phát hiện |
|---|---|---|
| `SQL_INJECTION` | Phát hiện tainted input chảy vào query raw | `DB::select("SELECT * FROM t WHERE x = " . $request->input('x'))`, `whereRaw()` với biến từ request |
| `UNSAFE_EVAL` | `eval()`, `assert()` với dữ liệu động | `eval($userInput);` |
| `HARDCODED_SECRET` | Secret/API key hardcode trong code | `'api_key' => 'sk-12345'`, regex bắt `sk-`, `AIza`, `AKIA`, `-----BEGIN PRIVATE KEY` |
| `MASS_ASSIGNMENT` | `Model::create($request->all())` không có `$fillable`/`$guarded` | `User::create($request->all());` |
| `UNSAFE_UNSERIALIZE` | `unserialize()` dữ liệu không tin cậy | `unserialize($cookie);` |
| `INSECURE_HASH` | Hash yếu | `md5()`, `sha1()` dùng cho mật khẩu |
| `LARAVEL_TAINT` | Chuỗi nội suy biến tainted vào query builder/`whereRaw` | `->whereRaw("price > $min")` |
| `DISABLED_CSRF` | `@csrf`/`VerifyCsrfToken` bị bỏ qua | Route `web` không dùng middleware CSRF |

> Taint tracking: phiên bản v1 dùng **heuristics theo pattern** (AST match) trước; v2 có thể nâng cấp lên data-flow taint (provenance map giữa hàm gọi) — xem Roadmap.

### 5.3 Missing Testcase Analyzers (severity: warning)

| Rule ID | Mô tả | Logic |
|---|---|---|
| `MISSING_CONTROLLER_TEST` | Controller trong `app/Http/Controllers/` không có test tương ứng | `app/.../UserController.php` ↔ `tests/Feature/UserControllerTest.php` hoặc `tests/Feature/Controllers/UserControllerTest.php` |
| `MISSING_SERVICE_TEST` | Service/Repository trong `app/Services/`, `app/Repositories/` thiếu test | map 1:1 sang `tests/Unit/...` |
| `MISSING_MODEL_TEST` | Model có logic phức tạp (method custom, scope, cast) không có test | scan method count + tìm file test tương ứng |
| `MISSING_FEATURE_COVERAGE` | Route/endpoint không có feature test nào chạm tới | parse `routes/`, đối chiếu tên action với test method (heuristic, v1) |
| `TEST_WITHOUT_ASSERT` | Test method tồn tại nhưng không có assertion | AST test method không chứa `assert*`, `expects*` |
| `LOW_TEST_RATIO` | Tỷ lệ test so với source thấp hơn ngưỡng | config `minRatio` (mặc định 0.3) |

> Map file test ↔ source: dùng quy ước thư mục + tên class (bỏ prefix, suffix `Controller`/`Service`/...). Kết quả warning, không fail CI mặc định.

### 5.4 Convention Analyzers (severity: info/warning)

| Rule ID | Mô tả | Ví dụ |
|---|---|---|
| `NAMING_CONVENTION` | Tên class/method/const lệch convention | controller không suffix `Controller`, method động từ không bắt đầu `is/has/get/set`... |
| `TODO_FIXME` | Còn TODO/FIXME/HACK trong code | `// TODO: fix later` |
| `DEAD_CODE` | Method/param không dùng (heuristic) | `public function helper()` không được gọi trong toàn codebase |
| `LARAVEL_PITFALL` | Anti-pattern Laravel | `DB::raw` ngoài migration, query trong view, `env()` ngoài config, `dd()`/`dump()` còn sót trong production code, sleep trong test |

---

## 6. Test coverage (tính tỷ lệ & threshold)

- Chỉ chạy khi có `phpunit --coverage-*` (cần `xdebug`/`pcov` active) — gọi JUnit XML có chứa coverage nếu cấu hình.
- Nếu không có extension coverage → checker này `skipped` + hint.
- Config: `phpunit.coverageThreshold` (mặc định 60% line coverage) → dưới ngưỡng tạo `Issue` (warning).

---

## 7. Reporters

### 7.1 Interface

```php
interface ReporterInterface
{
    public function render(array $results, CheckContext $ctx): void;
}
```

### 7.2 Chi tiết từng reporter

| Reporter | Output | Dùng cho |
|---|---|---|
| `ConsoleReporter` | Bảng tổng quan (Symfony Table): tên checker, status, số issue, duration, tổng điểm | Dev chạy tay |
| `JsonReporter` | `quality-report.json`: `{ generated_at, version, exit_code, summary, checkers: [ ... ] }` | CI/machine |
| `HtmlReporter` | `quality-report.html` (Blade template + inline CSS, tự đứng 1 file) | Share/archive |
| `MarkdownReporter` | `quality-report.md` (bảng + danh sách issue theo file) | Docs/PR comment |

### 7.3 JSON schema (trích đoạn)

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

### 8.1 Lệnh

```
php artisan quality:check [options]
```

### 8.2 Options

| Option | Mô tả | Mặc định |
|---|---|---|
| `--format=...` | `console` (mặc định), hoặc `console,json,html,md` cách nhau `,` để chạy nhiều | `console` |
| `--only=...` | Chỉ chạy checker được chỉ định, vd `phpcs,phpstan,custom` | tất cả |
| `--exclude=...` | Bỏ checker | — |
| `--path=...` | Ghi đè path scan | config |
| `--fail-on=severity` | Ngưỡng fail: `warning` | `error` | `critical` | `none` | `error` |
| `--output=...` | Thư mục xuất file report (mặc định `reports/quality-checker/`) | như trên |
| `--no-cache` | Bỏ cache kết quả analyzer | — |
| `--quiet` | Chỉ in tóm tắt | — |
| `--json` | Tương đương `--format=json` (shortcut) | — |
| `--ci` | Mode CI: mặc định `--format=json`, `--fail-on=error`, `--no-progress` | — |

### 8.3 Exit code

| Code | Ý nghĩa |
|---|---|
| `0` | Pass (không issue nào vượt ngưỡng `--fail-on`) |
| `1` | Có issue vượt ngưỡng (`error` trở lên mặc định) |
| `2` | Lỗi môi trường (tool thiếu, config lỗi) |
| `3` | Lỗi runtime của chính package |

---

## 8.5 Auto-provisioning tool thiếu

Khi checker không tìm thấy tool, package **tự giải quyết** thay vì chỉ báo `skipped`:

| Tool | Cơ chế tự cài |
|---|---|
| `phpcs` / `phpstan` / `phpunit` | `composer require --dev <package>` trong target project (qua `ToolInstaller`). |
| `trivy` | Tải binary từ GitHub releases (`TrivyDownloader`) vào cache per-user `~/.quality-checker/trivy`, không đụng project. |

Thứ tự ưu tiên khi tool thiếu:
1. **Auto-install** (nếu `auto_install_tools=true` và không có `--no-auto-install`).
2. **Fallback vendor package** — dùng tool đã có trong `vendor/bin` của chính package.
3. Nếu vẫn thiếu → `skipped` kèm **lệnh cài thủ công chính xác** (không còn message chung chung).

Quyết định:
- `--no-auto-install` / `auto_install_tools => false` để tắt (project air-gapped/read-only).
- Trivy version mặc định `0.74.0`, cấu hình qua `trivy.version`.
- `composer audit` chạy `--no-interaction`, timeout 120s, báo `error` (không phải `passed`) khi chính lệnh fail (offline/rate-limit).

---

## 9. Config (publish)

```php
// config/quality-checker.php
return [
    'paths' => ['app', 'routes', 'database', 'config', 'tests'], // đường dẫn scan mặc định
    'exclude' => [],

    // Tự cài tool thiếu: phpcs/phpstan/phpunit qua composer, trivy qua binary cached.
    'auto_install_tools' => true,

    // Cổng chất lượng: security | quality | all.
    'tier' => 'quality',

    // Ngưỡng confidence tối thiểu hiển thị: low | medium | high.
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
        'test_coverage' => [ // heuristic, mặc định TẮT
            'missing_controller_test' => false,
            'missing_service_test' => false,
            'missing_model_test' => false,
            'missing_feature_coverage' => false,
            'test_without_assert' => false,
        ],
        'convention' => [ // heuristic, mặc định TẮT
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

## 10. CI tích hợp (ví dụ)

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

### Phase 1 — MVP (tháng 1)
- [x] Cấu trúc package + ServiceProvider + command `quality:check`.
- [x] `PhpcsChecker`, `PhpstanChecker`, `PhpunitChecker`, `ComposerAuditChecker`.
- [x] `ConsoleReporter` + `JsonReporter`.
- [x] Exit code + `--only/--exclude/--fail-on`.
- [x] 3 security analyzer đầu (SQL injection, eval, hardcoded secret).
- [x] `MissingTestAnalyzer` cơ bản.
- [ ] Unit test cho package, CI của package.

### Phase 2 — Mở rộng (tháng 2)
- [ ] `HtmlReporter` + `MarkdownReporter` (Blade).
- [ ] `TrivyChecker`.
- [ ] Toàn bộ security + convention analyzers.
- [ ] Cache kết quả (`--no-cache`), parallel runner (multi-process).
- [ ] `--ci` mode, threshold config, coverage từ PHPUnit.

### Phase 3 — Nâng cao (tháng 3)
- [ ] Taint data-flow thực sự (provenance map qua call graph).
- [ ] Baseline (ghi nhận issue đã biết để chỉ báo issue mới).
- [ ] Giao diện `--fix` cho những lỗi auto-fixable (delegate phpcs fixer, php-cs-fixer).
- [ ] Hooks: pre-commit script, plugin cho IDE (PHPStorm/VS Code) nhúng report.

---

## 12. Rủi ro & lưu ý

| Rủi ro | Giảm thiểu |
|---|---|
| Tool chưa cài trong project | `isAvailable()` + status `skipped` + hint lệnh cài |
| Output tool thay đổi giữa version | Định vị bằng JSON schema chính thức (phpcs `--report=json`, phpstan `--error-format=json`), JUnit XML chuẩn |
| False positive của analyzer | Mỗi rule có `--only/--exclude` riêng, severity thấp cho heuristic, baseline ở Phase 3 |
| Perf khi scan codebase lớn | Parse theo file lazy, cache AST, parallel ở Phase 2 |
| PHP version không tương thích | `ParserFactory::createForNewestSupportedVersion()` + fallback theo composer.json |

---

## 13. Cần bạn xác nhận trước khi code

1. **Tên package / vendor namespace** — ví dụ `vietvang/quality-checker`?
2. **PHP phiên bản tối thiểu** hỗ trợ (8.1 / 8.2 / 8.3)?
3. **Laravel version range** hỗ trợ (10 / 11 / 12)?
4. **Ngưỡng mặc định** cho `fail_on` (error hay warning)?
5. Có cần **baseline** (bỏ qua issue cũ) ngay từ đầu không?
6. Có muốn **`--fix`** (auto-sửa phpcs) trong MVP không?

---

## 14. Confidence model & Tiering (giảm nhiễu)

Vấn đề: heuristic analyzer (dead code, missing test, naming, todo) tạo hàng nghìn
info/warning nuốt chửng vài finding bảo mật thật. Giải pháp:

### 14.1 Confidence
Mỗi `Issue` mang `confidence: high | medium | low` (enum `Confidence`, thứ tự 3>2>1).

| Confidence | Ý nghĩa | Ví dụ |
|---|---|---|
| **high** | Chắc chắn, có thể fail CI | OWASP, taint dataflow, hardcoded secret, SQL injection, composer audit |
| **medium** | Khá chắc, cảnh báo | `env()` ngoài config, `dd()` trong app, insecure hash |
| **low** | Gợi ý heuristic, mặc định ẩn | dead code, missing test, naming, todo/fixme |

- `--min-confidence=low|medium|high` lọc issue theo ngưỡng (mặc định `low` = hiện tất cả).
- `CheckRunner::shouldFail()` chỉ fail khi issue ≥ `min_confidence` và ≥ `fail_on` severity.

### 14.2 Tier (cổng chất lượng)
`--tier=security|quality|all` (mặc định `quality`, từ config `tier`).

| Tier | Fail khi | Dùng cho |
|---|---|---|
| `security` | Chỉ high-confidence issue bảo mật (OWASP/taint/secret/composer_audit) | CI gate bảo mật |
| `quality` | high+medium error/critical (kể cả phpcs/phpstan/phpunit) | CI gate chất lượng (mặc định) |
| `all` | Mọi thứ (gồm heuristic nếu bật) | Dev chạy tay |

Ở tier `security`, `shouldFail()` bỏ qua issue không phải `composer_audit` và có
confidence < high (tức chỉ fail trên finding bảo mật chắc chắn).

### 14.3 Heuristic mặc định TẮT
`analyzers.test_coverage.*` và `analyzers.convention.*` mặc định `false` (opt-in).
Chỉ security + owasp + tool checkers bật sẵn → đầu ra gọn, ít nhiễu.

### 14.4 Deduplicator
`src/Analyzers/Deduplicator.php` — gom issue trùng theo signature `md5(rule|file|line|message)`,
giữ bản confidence cao nhất. Giải quyết trùng lặp giữa `LaravelTaintAnalyzer` (heuristic)
và `TaintEngine` (dataflow).

---

## 15. OWASP Top 10 (2023) API mapping

Module `src/Analyzers/Owasp/`, prefix rule `OWASP_`, confidence **high**.

| Rule ID | Severity | OWASP | Analyzer |
|---|---|---|---|
| `OWASP_BROKEN_ACCESS_CONTROL` | Error | A01 Broken Access Control | `OwaspAccessControlAnalyzer` |
| `OWASP_SSRF` | Error | A10 Server-Side Request Forgery | `OwaspSsrfAnalyzer` |
| `OWASP_SSTI` | Error | A03 Injection (SSTI) | `OwaspSstiAnalyzer` |
| `OWASP_MISCONFIGURATION` | Warning | A05 Security Misconfiguration | `OwaspMisconfigurationAnalyzer` |
| `OWASP_COMMAND_INJECTION` | Critical | A03 Injection (Command) | `OwaspCommandInjectionAnalyzer` |
| `OWASP_XXE` | Error | A05 XML External Entity | `OwaspXxeAnalyzer` |

Cấu hình: `analyzers.owasp.{rule}` (mặc định `true`). Báo cáo thêm section OWASP:
- JSON: key `owasp` = `{ categories: {A01...: n}, total }`.
- Console/Markdown/HTML: bảng OWASP theo rule khi có `OWASP_*` issue.

### Detection tóm tắt
| Analyzer | Sink phát hiện | Bảo thủ |
|---|---|---|
| AccessControl | Controller method **mutating** (store/update/delete/... hoặc gọi save/delete/update/create) **không có** authorize/Gate/abort/middleware | Chỉ method mutating, bỏ magic/`__*` |
| SSRF | `file_get_contents/fopen/curl/Http::*/Guzzle` với URL không phải literal | Chỉ non-literal URL |
| SSTI | `Blade::render/compileString`, `view()->render()` với template không literal | Chỉ non-literal |
| Misconfiguration | `'debug'=>true`, `APP_DEBUG=true`, CORS `*`, secret placeholder | Chỉ match cụ thể, không suy diễn header |
| CommandInjection | `system/exec/shell_exec/passthru/proc_open/popen/Process` + input | Dùng `isTaintedExpr` |
| XXE | `simplexml_load_*/DOMDocument/SimpleXMLElement/XMLReader` không guard `libxml_disable_entity_loader` | Skip file nếu có guard |
