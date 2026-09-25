# So sánh với enlightn/enlightn / Comparison with Enlightn

Tài liệu này đối chiếu `vietvang/quality-checker` với
[enlightn/enlightn](https://github.com/enlightn/enlightn) (982 stars, 106 forks)
— tool audit Laravel nổi tiếng nhất ở mảng performance + security. Số liệu
Enlightn lấy từ README upstream tại thời điểm viết (repo đã **archived,
read-only từ 01/2026**).

_This note compares `vietvang/quality-checker` against Enlightn. Enlightn
figures come from its upstream README; that repo is archived since Jan 2026._

## 1. Tổng quan / Overview

| Tiêu chí | quality-checker (v1.0.0) | enlightn/enlightn (OSS) |
|---|---|---|
| Trạng thái | Active | Archived 01/2026, read-only |
| Số check | ~27 custom rules + 5 tool gates (phpcs/phpstan/phpunit/composer-audit/trivy) | 66 checks OSS (131 với Pro thương mại) |
| Nhóm check | Security (OWASP Top 10) + migration/validation + coverage + convention | Performance (37) + security (49) + reliability (45), tính cả bản Pro |
| Triết lý phân tích | Static, **không boot Laravel** | Boot app + **dynamic analysis** |
| Laravel support | Pilot tới Laravel 12 | Dừng ở Laravel 11 |
| OS support | Windows + Linux/macOS (test chính trên Windows) | Chỉ macOS/Linux, **không hỗ trợ Windows** |

## 2. Điểm Enlightn hơn / Where Enlightn wins

- **Runtime/dynamic analysis**: phát hiện N+1 query, duplicate/slow query,
  opcache tuning, cache hit ratio, health checks (DB/Redis/disk/migrations),
  server config — những thứ static analysis không bao giờ thấy được.
- **Độ phủ**: 66 checks OSS trên 3 mảng perf/security/reliability; mỗi check
  có trang docs riêng.
- **Hệ sinh thái**: Web UI dashboard, GitHub bot review comments, scheduled
  runs — đổi lại là dịch vụ thương mại (vendor lock-in).

## 3. Điểm quality-checker hơn / Where quality-checker wins

- **Còn sống**: Enlightn dừng phát triển cùng Laravel ≤ 11; tool này active,
  tag semver (`v1.0.0`), CI dogfooding.
- **Chạy được mọi nơi**: không cần boot app — scan được cả project hỏng
  `.env`/thiếu DB (một pilot e-commerce); hỗ trợ Windows.
- **Report mở, self-hosted**: SARIF 2.1.0 (GitHub code scanning native) +
  HTML/JSON/Markdown/console, không phụ thuộc dịch vụ ngoài.
- **Static precision đo được**: corpus labeled 26 cases, precision/recall
  1.000/1.000 pin bằng test (`tests/Unit/AnalyzerMetricsTest.php`) —
  Enlightn không công bố metrics này.
- **Static depth riêng có**: route-middleware awareness cho broken access
  control (middleware chains, `Route::controller()`, cross-file `require`,
  FQCN keys), taint engine, migration restore detection — mảng static mà
  Enlightn OSS cũng chỉ làm heuristic.
- **Suppression 2 tầng**: baseline file + inline
  `// quality-checker-ignore RULE` (Enlightn chỉ có baseline).
- **Cache an toàn nâng cấp**: cache key hash cả analyzer source, package
  upgrade không bao giờ phục vụ kết quả cũ.

## 4. Định hướng / Direction

Không đua số check runtime với Enlightn (đòi boot app + production env,
phức tạp và đã có người làm tốt). Đào sâu **static precision** — đúng mảng
Enlightn OSS yếu và đã bỏ cuộc: thêm rule mới luôn kèm corpus TP/FP để
precision/recall không tụt, validate trên pilot repo thật trước khi merge.
