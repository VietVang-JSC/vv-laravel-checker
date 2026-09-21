# Baseline — ghi nhận issue đã biết

Baseline cho phép bạn "chấp nhận" các issue hiện có để từ đó chỉ báo cáo những
issue **mới** phát sinh sau này. Hữu ích khi đưa quality-checker vào một dự án
đã có sẵn nhiều lỗi mà bạn chưa muốn xử lý ngay.

## Cách dùng

### 1. Sinh baseline từ kết quả hiện tại

Chạy kiểm tra và xuất JSON, sau đó tạo baseline từ toàn bộ issue hiện có:

```bash
php artisan quality:check --format=json --output=reports/quality-checker
php artisan quality:check --baseline-generate
```

Lệnh `--baseline-generate` đọc kết quả kiểm tra và ghi file baseline (mặc định
`baseline.json` ở thư mục gốc dự án).

### 2. Cập nhật baseline

Khi bạn sửa một số lỗi và muốn "đóng băng" trạng thái mới làm baseline:

```bash
php artisan quality:check --baseline-update
```

Lệnh `--baseline-update` ghi đè baseline bằng **toàn bộ** issue hiện tại (mọi
mức severity). Chỉ nên dùng khi bạn chắc chắn trạng thái hiện tại là mong muốn.

### 3. Chỉ định file baseline tùy chọn

```bash
php artisan quality:check --baseline-file=reports/baseline.json
```

## File baseline

File là JSON đơn giản, chứa danh sách signature (không thể đọc bằng mắt):

```json
{
  "generated_at": "2026-09-20T10:00:00+07:00",
  "baseline": [
    "9f2c1d8a3b7e4f5a..."
  ]
}
```

Mỗi signature là `md5(rule|file|line|message)`. Khi có baseline được tải, các
issue trùng signature sẽ bị bỏ qua trong báo cáo (nhưng vẫn được đánh dấu
`baselined` nếu cần hiển thị).

## Gitignore

Tuỳ theo đội, bạn có thể chọn:

- **Không commit baseline** (mỗi thành viên tự tạo):
  ```gitignore
  baseline.json
  ```
- **Commit baseline chung** (đội dùng chung, đồng bộ qua git): bỏ dòng trên.

Mặc định package khuyên **commit** để cả đội thống nhất ngưỡng chất lượng, trừ
khi bạn muốn mỗi người có baseline riêng.

> Lưu ý: Các flag `--baseline-generate`, `--baseline-update`, `--baseline-file`
> được nối vào command trong bước tích hợp. Nếu command chưa hỗ trợ, vui lòng
> kiểm tra phiên bản package đã có đủ chức năng baseline.
