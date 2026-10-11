# Project Overview — Rampart Quality Checker

**A comprehensive quality gate for Laravel** — wraps `phpcs`, `phpstan`, `phpunit`, `composer audit`, `npm audit`, `trivy` and adds 50 custom PHP-Parser rules for security, missing tests and conventions.

## What it does
- One command `php artisan quality:check` or standalone `php bin/quality-check <target>` — same engine, same reports, same exit codes.
- 50 rules: OWASP Top 10 2021 (11), Security (12), Taint (4, opt-in), Laravel (3), Test Coverage (7), Convention (6, opt-in), Frontend (3: JS/CSS/Blade stack), Ops (2: perms/EOL), Forensics (2: rogue PHP/obfuscated). See `src/Result/RuleIds.php` and `README.md` rule tables (enforced by `RuleDocsTest`).
- 500 labeled cases `tests/Unit/AnalyzerMetricsTest.php` `340 TP+160 TN` `1.000/1.000` + 98 holdout blind + 30 CVE recall `30/30` + 8 `trivy` + 5 `npm audit` contract tests. `1393` tests green, `phpstan` level 6, `phpcs` PSR12.
- Reports: `console`, `json`, `html` (self-contained, searchable, dark mode, code snippets), `md` (mermaid pie), `sarif` for GitHub code scanning. Sample external precision via `tools/sample-findings.php` + `tools/inter-rater.php` (kappa ≥0.9).

## How to use (5 min)
```bash
composer require rampart/quality-checker --dev
php artisan vendor:publish --tag=quality-checker-config
php artisan quality:check --tier=security --only=custom,composer_audit # first run
php artisan quality:check --format=all --output=reports/quality-checker
```
Standalone (no install in target):
```bash
git clone https://github.com/thiennhant95/Rampart.git && composer install
php bin/quality-check /path/to/project --tier=security --fail-on=none
```

## Where things live
- Rule ids / OWASP categories: `src/Result/RuleIds.php`
- Config defaults: `config/quality-checker.php` (`frontend.js_syntax/css_syntax/blade_stack` on by default)
- Precision corpus: `tests/Unit/AnalyzerMetricsTest.php`
- Docs map: `docs/index.md`

## Status
- Latest: `v1.5.3` (2026-10-11) — corpus 500, Laravel 13, npm audit, ops/forensics, sink-first perf (-79% traversals), `SKILL.md` agent-native.
- License: MIT.

