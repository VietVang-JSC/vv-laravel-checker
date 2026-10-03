# Upgrade guide

Breaking changes per release, newest first. This package is on the `0.x` line,
so anything that changes behaviour is called out here rather than hidden in the
[CHANGELOG](CHANGELOG.md).

Run the version you are coming from, read the entries between it and your target,
then re-baseline (below) — every behavioural change here moves findings, so a
stale baseline is how upgrades silently pass.

---

## Upgrading to 0.8.x from 0.7.x

### `analyzers.exclude_paths` now excludes fixtures by default

**This can make findings disappear.** The custom analyzers previously had no way
to skip a directory: `analyzers.exclude` and `--exclude` filter *checker names*,
not files, so code under `tests/fixtures` — which exists to be vulnerable —
was reported like production code.

The shipped default is now:

```php
'analyzers' => [
    'exclude_paths' => ['*/fixtures/*'],
],
```

If your fixture findings were meaningful signal for you (you point the tool at a
fixtures directory on purpose, for example), opt out explicitly:

```php
'analyzers' => [
    'exclude_paths' => [],
],
```

To extend the list rather than replace it:

```php
'exclude_paths' => ['*/fixtures/*', 'database/seeds/*', 'tests/Stubs'],
```

Or per run, without touching config:

```bash
php artisan quality:check --exclude-path='*/stubs/*' --exclude-path='*/samples/*'
```

Excluded files are counted in the `custom` checker summary
(`N file(s) excluded by analyzers.exclude_paths`), so a scan never hides scope
silently. Matching is case-insensitive and works with either path separator.

### Reports show a real version

`bin/quality-check` used to stamp every report `v0.0.0`, because the standalone
runner never resolved a version while the Artisan command did. Both now resolve
it from `composer.json`, then from Composer's runtime metadata, so reports show
`v0.7.0` on an installed package and `dev-main` in a git checkout.

**Impact:** baseline signatures and any script parsing the report header must not
assume `v0.0.0`. JSON consumers should read `package_version` rather than
matching a literal.

### `.env` files inside `vendor` are no longer analyzed

`collectEnvFiles()` resolved `.env` / `.env.example` without the vendor guard the
PHP and Blade collectors already applied. If your application root lives inside
`vendor` (Testbench-based tooling), a dependency's `.env.example` was analyzed as
your own config. It no longer is. If you deliberately ship a `.env` inside a
`vendor/` path, pass it explicitly with `--path`.

---

## Upgrading to 0.7.0 from 0.6.x

- **Report actionability across all five formats**: each finding carries a
  remediation entry, and console/JSON/HTML/Markdown/SARIF all surface it.
- **`OWASP_BLADE_DYNAMIC_INCLUDE` added** (A01 Path Traversal, dynamic
  `@include` target).
- **Priority pill encoding fixed** in the HTML report.

## Upgrading to 0.6.2 from 0.6.1

- **Ownership production mapping**: `OWASP_OWNERSHIP_IDOR` findings now carry the
  production-path evidence needed to act on them.

## Upgrading to 0.6.1 from 0.6.0

- **Ownership reason taxonomy** plus shadow-run mining against real
  repositories. Shadow decisions are non-gating: they enrich evidence, they do
  not change a verdict.
- Zero new findings on the tracked corpora — precision and recall stayed at
  1.000/1.000 across the 197-case labelled corpus.

## Upgrading to 0.6.0 from 0.5.x

- **New analyzer group** for the OWASP Top 10 (2021): broken access control,
  ownership/IDOR, path traversal, SSRF, SSTI, command injection, blade XSS,
  misconfiguration, XXE, open redirect. All on by default.
- New option `--ignore=<RULE_ID>` and config `quality_gate.ignore` to exempt
  specific rules from the gate.
- Inline suppression (`// quality-checker-ignore RULE`) is on by default.

## Renumbering: the `1.0.0` / `1.1.0` tags

Two releases were tagged `v1.0.0` and `v1.1.0` before the package was
renumbered onto the `0.x` line starting at `v0.2`. Those tags exist but are not
part of the release sequence.

**If you pinned `^1.0` or `^1.1`, you are on a dead line.** Move to the latest
`0.x`; the API is not compatible with `1.x`, and the changelog entry that
describes the renumbering is kept in
[CHANGELOG.md](CHANGELOG.md#026--061---2026-09-28----2026-09-30).

---

## Re-baselining after an upgrade

Findings move between releases in both directions, so an old baseline is worse
than none — it hides the new findings while keeping the fixed ones.

```bash
# 1. See what the new version reports, ignoring the old baseline.
php artisan quality:check --baseline-file=/dev/null --format=md

# 2. Once you have reviewed the diff, rewrite the baseline.
php artisan quality:check --baseline-update

# 3. Commit the updated baseline.json.
```

On CI, regenerate the baseline in a branch and review the diff — an unexpected
jump in baseline size is usually a new rule firing on your whole codebase, which
is information, not noise.

## Checking what changed in an upgrade

```bash
# Rules added or removed between two versions:
git diff v0.7.0..HEAD -- src/Result/RuleIds.php

# Behaviour changes to the analyzers:
git diff v0.7.0..HEAD -- src/Analyzers src/Checkers
```

`src/Result/RuleIds.php` is the registry of every rule id the package can emit,
so a diff of that one file tells you whether your `quality_gate.ignore` list
still refers to rules that exist.