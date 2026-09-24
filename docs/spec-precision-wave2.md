# Spec — Precision Wave 2: 3 analyzer families mới

> Mục tiêu: đào sâu **static precision** (mảng Enlightn bỏ cuộc) — thêm 3 rule
> families Laravel-specific, mỗi rule kèm corpus TP/FP để precision/recall
> không tụt. Xem `docs/comparison-enlightn.md` §4.

## 1. Phân công (3 agents song song)

| Agent | Rule | Rule ID | Config key | Severity / Confidence |
|---|---|---|---|---|
| A | Open Redirect | `OWASP_OPEN_REDIRECT` | `owasp.open_redirect` | Error / High |
| B | Path Traversal | `OWASP_PATH_TRAVERSAL` | `owasp.path_traversal` | Error / High |
| C | Blade unescaped echo XSS | `OWASP_BLADE_XSS` | `owasp.blade_xss` | Error / High |

## 2. Ngữ nghĩa từng rule (bắt buộc)

### Agent A — Open Redirect (`src/Analyzers/Owasp/OwaspOpenRedirectAnalyzer.php`)

Flag khi target của redirect không phải literal và không chứng minh được an toàn:

- Sinks: `redirect($target)`, `redirect()->away($t)`, `redirect()->to($t)`,
  `Redirect::away($t)`, `Redirect::to($t)`, `Redirect::route(...)` — KHÔNG flag
  (`route()` an toàn theo định nghĩa), `back()` / `redirect()->back()` — KHÔNG flag.
- Safe (skip): string literal, `route(...)` / `back()` / `url()->previous()` calls,
  `config()` / `env()` lookups.
- Flag: Variable, PropertyFetch, MethodCall, FuncCall khác, Concat/Interpolation
  (trừ khi mọi leaf đều safe theo định nghĩa trên).
- TP mẫu: `return redirect($request->input('next'));`
- FP mẫu (phải im): `return redirect()->route('home');`,
  `return redirect(config('app.url') . '/done');`

### Agent B — Path Traversal (`src/Analyzers/Owasp/OwaspPathTraversalAnalyzer.php`)

Flag khi file sink nhận path tainted mà không qua `basename()`:

- Sinks (arg 0): `file_get_contents`, `file_put_contents`, `fopen`, `file`,
  `readfile`, `include`/`require`/`include_once`/`require_once` với expr động,
  `Storage::get/put/delete/download`, `response()->download/file`.
- Safe (skip): string literal, `basename(...)`-wrapped expr, `storage_path()`/
  `base_path()` với args toàn literal, `env()/config()` (deploy-time).
- Flag: Variable, PropertyFetch, MethodCall, Concat/Interpolation chứa phần động.
- TP mẫu: `return response()->download(storage_path('docs/' . $request->file));`
  (`basename()` không có → flag đúng).
- FP mẫu (phải im): `file_get_contents(storage_path('app/' . basename($name)));`

### Agent C — Blade XSS (`src/Analyzers/Owasp/OwaspBladeXssAnalyzer.php`)

Flag `{!! ... !!}` chứa dữ liệu động trong file `.blade.php`:

- Override `supports()` để nhận `*.blade.php` (KHÔNG sửa `collectFiles` —
  phần đó do integrator làm).
- Flag block `{!!` nào chứa ký tự `$` (biến) hoặc `request(`.
- Skip block không có `$` (vd `{!! csrf_field() !!}` — pure function call)
  và block chứa `e(` (đã escape thủ công).
- Dùng regex/tokenizer trên raw content (blade không phải PHP hợp lệ,
  KHÔNG dùng PHP-Parser cho file này).
- TP mẫu: `<div>{!! $comment->body !!}</div>`
- FP mẫu (phải im): `{!! csrf_field() !!}`, `{{ $name }}` (escaped syntax).

## 3. Quy ước chung (bắt buộc cả 3)

- Namespace/file theo mẫu `OwaspXxeAnalyzer`; class `final`, `extends AbstractAnalyzer`
  (riêng agent C vẫn extends nhưng override `supports()`).
- Class docblock ghi rõ Assumes + "Deliberately not flagged".
- Issue qua `$this->makeIssue(RULE, msg, $file, $line, Severity::Error, ['sink' => ...])`.
- Kiểu đầy đủ cho phpstan level 6 (xem `OwaspSsrfAnalyzer` làm mẫu).
- PSR-12 (chạy `vendor/bin/phpcs` lên file mới trước khi xong).

## 4. Ranh giới file (CHỐNG CONFLICT — tuân thủ tuyệt đối)

- Mỗi agent CHỈ ĐƯỢC TẠO 2 file mới (tên trong §2 + `tests/Unit/<Rule>AnalyzerTest.php`,
  vd `tests/Unit/OwaspOpenRedirectAnalyzerTest.php`, ≥ 6 tests TP/FP).
- **CẤM** sửa file chung: `CustomAnalyzerChecker.php`, `config/*`,
  `AnalyzerMetricsTest.php`, `docs/*`, `CHANGELOG.md`, `README.md`.
- Verify bằng `vendor/bin/phpunit --filter <TenTestCuaMinh> --do-not-cache-result`
  (KHÔNG chạy full `composer check` để tránh clash cache giữa agents).
- Khi xong, trả về đúng 5 mục: (1) tóm tắt rule, (2) dòng wiring
  `entry(...)` cho `buildAnalyzers()`, (3) dòng config cho `owasp` section,
  (4) 4+ corpus cases theo format `AnalyzerMetricsTest::corpus()`
  (string content dùng double-quote với `\$` escape), (5) 1 đoạn docs cho
  `docs/false-positives.md` + 1 dòng CHANGELOG.

## 5. Integration (integrator làm sau, không phải việc agents)

Wire checker + config + corpus + docs + `collectFiles` hỗ trợ `*.blade.php`
+ full `composer check` + re-scan pilot kiểm FP + commit + push.
