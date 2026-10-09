# Rampart Quality Checker — Agent Skill

Use this skill when you need to run a comprehensive Laravel quality gate.

## When to use
- Before opening a PR, after `composer install`, or in CI.
- When the user asks for `quality:check`, `phpcs`, `phpstan`, `phpunit`, `composer audit`, `npm audit`, or security scan.

## Commands

### Zero-config (recommended)
```bash
php artisan quality:check --tier=security --only=custom,composer_audit
php artisan quality:check --format=all --output=reports/quality-checker
```

### Standalone (no install in target)
```bash
git clone https://github.com/thiennhant95/Rampart.git && composer install --no-interaction
php bin/quality-check /path/to/project --tier=security --fail-on=none --format=json --output=/tmp/out
php tools/sample-findings.php /tmp/out/quality-report.json --n=100 --seed=42 --out=sample.csv
php tools/inter-rater.php reviewer1.csv reviewer2.csv
```

### Frontend checks (JS/CSS/Blade)
```bash
php bin/quality-check /path --only=custom --tier=quality # includes JS_SYNTAX_ERROR, CSS_SYNTAX_ERROR, BLADE_STACK_MISMATCH
```

### Supply-chain
```bash
php artisan quality:check --only=composer_audit,npm_audit
```

### Forensics (post-hack)
```bash
php bin/quality-check /path --only=custom --tier=security # includes ROGUE_PHP, OBFUSCATED_PHP
```

## Outputs
- `quality-report.html` — self-contained, searchable, dark mode, code snippets
- `quality-report.json` — machine-readable for CI
- `quality-report.md` — with mermaid pie
- `quality-report.sarif` — GitHub code scanning

## Gate
- Exit `0` passed, `1` failed, `2` bad invocation, `3` internal error.
- Use `--fail-on=none` to review without failing, then `--baseline-generate`.

## Notes
- Requires PHP 8.1+, Laravel 9-13, Composer 2.4+, Node for `npm audit` (optional).
- First run may need `php artisan vendor:publish --tag=quality-checker-config`.
- Memory: use `php -d memory_limit=1G` for large projects.

## New in v1.4.0+ (checkpoint/scalpel parity)
- `npm audit` (supply-chain), `PERMS_TOO_OPEN` (777), `EOL_COMPONENT` (Laravel/PHP EOL)
- `ROGUE_PHP` (public/*.php), `OBFUSCATED_PHP` (eval/base64)
- `JS/CSS` syntax + `BLADE_STACK` (`@push`/`@stack`)

