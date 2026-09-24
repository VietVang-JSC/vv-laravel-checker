# False positives — xử lý cảnh báo sai / Handling false positives

Custom analyzers của package là **static heuristics**, không phải verifier có
độ chính xác tuyệt đối. Tài liệu này giúp bạn phân biệt finding thật với cảnh
báo sai, và xử lý đúng cách thay vì tắt cả nhóm rule.

_The package's custom analyzers are static heuristics, not sound verifiers.
This guide helps you tell real findings from noise and handle them properly
instead of disabling whole rule groups._

## 1. Nguyên tắc / Principles

1. **Đọc finding trước, quyết định sau** — mỗi issue có file + line + rule +
   message. Mở đúng dòng đó trước khi làm gì khác.
2. **Sửa code trước, baseline sau** — nếu code có thể viết lại cho an toàn hơn
   (binding tham số, validation, `$fillable`), hãy sửa code.
3. **Baseline từng finding đã review** — chỉ `--baseline-generate`/`--update`
   sau khi đã đọc hết báo cáo. Baseline mù = che cả lỗi thật.
4. **Không tắt rule `high` confidence diện rộng** — nếu ồn, tăng
   `--min-confidence` hoặc đổi `--tier` thay vì tắt `analyzers.security.*`.

## 2. Mức tin cậy & hành động / Confidence & action

| Confidence | Ví dụ | Hành động khuyên dùng |
|---|---|---|
| `high` | `SQL_INJECTION`, `UNSAFE_EVAL`, `HARDCODED_SECRET`, `OWASP_*`, `TAINT_*`, `composer_audit` | Coi như lỗi thật cho tới khi chứng minh ngược lại. Sửa code, không baseline vội. |
| `medium` | `INSECURE_HASH`, `LARAVEL_PITFALL` (`dd()`/`env()`), `MIGRATION_*`, `ROUTE_MISSING_VALIDATION` | Thường đúng. Kiểm tra ngữ cảnh (môi trường test? file config?) rồi sửa hoặc baseline. |
| `low` | `DEAD_CODE`, `NAMING_CONVENTION`, `TODO_FIXME`, `MISSING_*_TEST` | Gợi ý heuristic. Bật opt-in khi dọn code, đừng gate CI bằng nhóm này. |

Lọc nhanh khi review:

```bash
# Chỉ xem finding chắc chắn (ít nhiễu nhất)
php artisan quality:check --min-confidence=high --tier=security

# Gate CI chất lượng chuẩn (mặc định của package)
php artisan quality:check --tier=quality

# Xem tất cả kể cả heuristic khi dọn code local
php artisan quality:check --tier=all --fail-on=none
```

## 3. Các cảnh báo sai thường gặp / Common false positives

### `SQL_INJECTION` / `TAINT_SQL_INJECTION` / `LARAVEL_TAINT`
- **Báo đúng khi**: input từ request (`$request->input()`, `$_GET`, ...) nối
  chuỗi hoặc nội suy vào `DB::select`, `whereRaw`, `selectRaw`, ...
- **Sai khi**: biến trùng tên với biến tainted nhưng đã được gán lại giá trị
  sạch; query builder dùng binding (`where('id', $id)`) — analyzer bỏ qua
  trường hợp này, nếu vẫn báo hãy kiểm tra kỹ vì có thể là taint thật qua
  biến trung gian.
- **Sửa đúng**: dùng binding/parameter thay vì nối chuỗi:
  ```php
  DB::select('select * from users where id = ?', [$id]);
  ```

### `MASS_ASSIGNMENT`
- **Báo đúng khi**: `Model::create($request->all())` mà model không có
  `$fillable`/`$guarded`.
- **Sai khi**: model nằm ngoài đường dẫn scan (analyzer không resolve được
  file model nên **không báo** — fail-open). Nếu project tách model ra khỏi
  `app/`, hãy thêm path scan chứa model để rule này có tác dụng.
- **Sửa đúng**: khai báo `$fillable` hoặc dùng FormRequest + `validated()`.

### `OWASP_BROKEN_ACCESS_CONTROL`
- **Báo đúng khi**: action mutating (`store`/`update`/`destroy`/...) không thấy
  `authorize()`, `Gate::`, `$this->authorize()`, `abort()`, middleware.
- **Sai khi**: phân quyền đặt ở route middleware, policy tự động, hoặc base
  controller — analyzer chỉ nhìn trong thân method nên không thấy.
- **Xử lý**: nếu phân quyền nằm ngoài method, review một lần rồi baseline
  finding đó (đừng tắt cả rule).
- **Case pilot (Bagisto/LienHoaEc)**: rule báo **453 lần** trên admin
  controllers. Bagisto kiểm quyền qua route middleware (`bouncer::permission`,
  policy registration trong `RouteServiceProvider`) chứ không gọi
  `authorize()` trong method — classic false positive đã mô tả ở trên.
  Kỳ vọng với framework dùng middleware-based auth: số lượng finding lớn
  là bình thường; review theo mẫu (1 file) rồi baseline cả nhóm thay vì
  tắt rule.

### `OWASP_SSRF` / `OWASP_COMMAND_INJECTION` / `OWASP_SSTI`
- Engine chỉ báo khi URL/template/lệnh **không phải literal** và có dấu vết
  input người dùng. Nếu giá trị đã qua allow-list/validate chặt, review rồi
  baseline thay vì tắt rule.

### `HARDCODED_SECRET`
- Regex bắt `sk-`, `AIza`, `AKIA`, private key, ... **Chuỗi test/fixture cũng
  bị bắt** — đó là hành vi có chủ ý. Với fixture test, hoặc dùng giá trị
  giả rõ ràng không khớp pattern, hoặc loại trừ thư mục test khỏi path scan
  security.
- Placeholder như `xxx`, `changeme`, empty string trong file config được báo
  bởi `OWASP_MISCONFIGURATION` (mức warning) — hãy thay bằng `env()`.

### Nhóm heuristic `low` (`DEAD_CODE`, `NAMING_CONVENTION`, `TODO_FIXME`, `MISSING_*_TEST`)
- Mặc định **TẮT** (`analyzers.test_coverage.*`, `analyzers.convention.*` =
  `false`). Nếu bạn bật lên và thấy hàng loạt cảnh báo, đó là kỳ vọng —
  đừng baseline hàng loạt, hãy tắt lại và chỉ bật khi dọn code theo chủ đề.

## 4. Quy trình review đề xuất / Suggested review flow

```bash
# 1. Xem toàn cảnh, không fail
php artisan quality:check --format=all --fail-on=none

# 2. Tập trung finding chắc chắn trước
php artisan quality:check --min-confidence=high --tier=security --fail-on=none

# 3. Sửa code những gì sửa được (binding, fillable, validation, authorize)

# 4. Chấp nhận phần còn lại đã review làm baseline
php artisan quality:check --baseline-generate

# 5. Từ nay CI chỉ fail trên finding MỚI
php artisan quality:check --ci --baseline-file=baseline.json
```

Commit `baseline.json` để cả đội dùng chung ngưỡng. Chỉ chạy
`--baseline-update` sau khi đã review lại toàn bộ báo cáo mới.

## 5. Những điều không nên làm / Don'ts

- Đừng thêm `baseline.json` vào `.gitignore` **và đồng thời** than phiền CI
  mỗi máy báo khác nhau — baseline không commit thì mỗi người một ngưỡng.
- Đừng `--fail-on=none` trong CI để "cho xanh" — flag đó chỉ dùng khi review.
- Đừng tắt `analyzers.security` / `analyzers.owasp` vì một finding sai —
  baseline đúng finding đó, giữ rule lại để bắt lỗi mới.
