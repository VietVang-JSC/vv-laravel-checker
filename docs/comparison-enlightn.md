# Comparison with Enlightn

This note compares `vietvang/quality-checker` against
[enlightn/enlightn](https://github.com/enlightn/enlightn) (982 stars, 106 forks)
— the best-known Laravel audit tool for performance + security. Enlightn
figures come from the upstream README at the time of writing (the repo has been **archived,
read-only since 01/2026**).

_This note compares `vietvang/quality-checker` against Enlightn. Enlightn
figures come from its upstream README; that repo is archived since Jan 2026._

## 1. Overview

| Criterion | quality-checker (v1.0.0) | enlightn/enlightn (OSS) |
|---|---|---|
| Status | Active | Archived 01/2026, read-only |
| Check count | ~27 custom rules + 5 tool gates (phpcs/phpstan/phpunit/composer-audit/trivy) | 66 checks OSS (131 with commercial Pro) |
| Check groups | Security (OWASP Top 10) + migration/validation + coverage + convention | Performance (37) + security (49) + reliability (45), including the Pro version |
| Analysis philosophy | Static, **no Laravel boot** | Boot app + **dynamic analysis** |
| Laravel support | Pilot up to Laravel 12 | Stops at Laravel 11 |
| OS support | Windows + Linux/macOS (mainly tested on Windows) | macOS/Linux only, **no Windows support** |

## 2. Where Enlightn wins

- **Runtime/dynamic analysis**: detects N+1 queries, duplicate/slow queries,
  opcache tuning, cache hit ratio, health checks (DB/Redis/disk/migrations),
  server config — things static analysis can never see.
- **Coverage**: 66 OSS checks across 3 areas: perf/security/reliability; each check
  has its own docs page.
- **Ecosystem**: Web UI dashboard, GitHub bot review comments, scheduled
  runs — in exchange for a commercial service (vendor lock-in).

## 3. Where quality-checker wins

- **Still alive**: Enlightn stopped development at Laravel ≤ 11; this tool is active,
  with semver tags (`v1.0.0`), CI dogfooding.
- **Runs anywhere**: no app boot needed — it can scan even broken projects with
  a bad `.env`/missing DB (one e-commerce pilot); Windows supported.
- **Open, self-hosted reports**: SARIF 2.1.0 (native GitHub code scanning) +
  HTML/JSON/Markdown/console, with no dependency on external services.
- **Measured static precision**: 26-case labeled corpus, precision/recall
  1.000/1.000 pinned by tests (`tests/Unit/AnalyzerMetricsTest.php`) —
  Enlightn publishes no such metrics.
- **Its own static depth**: route-middleware awareness for broken access
  control (middleware chains, `Route::controller()`, cross-file `require`,
  FQCN keys), taint engine, migration restore detection — static areas where
  Enlightn OSS only used heuristics too.
- **Two-layer suppression**: baseline file + inline
  `// quality-checker-ignore RULE` (Enlightn only has a baseline).
- **Upgrade-safe cache**: the cache key hashes the analyzer source, so a package
  upgrade never serves stale results.

## 4. Direction

Not competing on runtime check count with Enlightn (which requires booting the app + a production env,
complex, and already done well by others). Going deeper on **static precision** — exactly the area
where Enlightn OSS was weak and gave up: every new rule ships with a TP/FP corpus so
precision/recall never regress, validated on real pilot repos before merge.
