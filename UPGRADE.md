# Upgrade guide

Breaking changes per release, newest first. The current line is `1.x`
(`v1.2.0` onwards, after `v0.9.0`); anything that changes behaviour is called
out here rather than hidden in the [CHANGELOG](CHANGELOG.md).

Run the version you are coming from, read the entries between it and your target,
then re-baseline (below) — every behavioural change here moves findings, so a
stale baseline is how upgrades silently pass.

---

## Upgrading to 1.4.0 from 1.3.x

No breaking changes. The labelled corpus grew from 400 to 500 shapes; no rule,
severity or default changed.

## Upgrading to 1.3.0 from 1.2.x

### `PHPUNIT_LOW_COVERAGE` is now `error`

**This can make builds fail.** The finding `phpunit` emits when line coverage is
below `phpunit.coverageThreshold` (default `60`) was `warning`, so the shipped
`fail-on=error` never gated on it. It is now `error`, which is what the config
key promised. Either raise coverage, lower `coverageThreshold`, or add
`PHPUNIT_LOW_COVERAGE` to `quality_gate.ignore`.

### Frontend analyzers are on by default

**This can make findings appear.** `JS_SYNTAX_ERROR`, `CSS_SYNTAX_ERROR` and
`BLADE_STACK_MISMATCH` scan `resources/` and `public/` and ship enabled
(`analyzers.frontend`). The first two are `warning`; `BLADE_STACK_MISMATCH` is
`error` only for an unclosed `@push`. Set the keys to `false` to opt out.

## Upgrading to 1.2.0 from 0.9.x

### Version line

`1.2.0` follows `0.9.0` directly. The number resumes the `1.x` line that
`v1.0.0` / `v1.1.0` briefly occupied in September 2026 (see
[Renumbering](#renumbering-the-100--110-tags) below); the API in `1.2.0` is the
`0.9.0` API, not the one those two tags shipped. If you had `^0.9`, move to
`^1.2`.

### Analyzers now resolve paths against the scanned project

**This can make findings move.** `FeatureTestAnalyzer`, `ControllerTestAnalyzer`
and `NamingConventionAnalyzer` used the caller's working directory to find
`routes/`, `app/` and `tests/`. When the standalone binary scanned another
project, they read the caller's directories and attributed the result to the
target. They now use the scanned project's root, so `MISSING_FEATURE_COVERAGE`
and `NAMING_CONVENTION` findings may appear or disappear on the first run.

## Upgrading to 0.9.0 from 0.8.x

### Auto-installed phpcs is now version-constrained

**This can make findings disappear.** `auto_install_tools` used to install
`squizlabs/php_codesniffer` with no constraint, so a fresh project got phpcs 4.x.
Its PSR12 ruleset is re-implemented and additionally reports `Squiz.*` codes that
3.x does not. Auto-install now asks for `^3.13 || ^4.0`, the range this package is
verified against, which means a new install gets 3.x and those extra codes stop
appearing.

If you already have phpcs 4.x installed and want to keep it, nothing changes —
the constraint only applies to what this package installs for you. To see the codes
your own phpcs reports:

```bash
vendor/bin/phpcs --standard=PSR12 -s app | grep Squiz
```

### A `composer.phar` in the project root is now actually used

**This can make findings appear.** `composer_audit` resolved a project-local
`composer.phar` by joining the interpreter and the path into a single string,
which Symfony's `Process` then tried to execute as one binary name. The spawn
failed and the audit was reported as skipped. It now runs, so a project shipping
its own phar gets real advisory results instead of a skip. Same fix applies to
`auto_install_tools`, which was silently failing to install anything.

### Whitespace-only PHPStan notices are no longer findings

`phpstan` writes file-level notices — an unmatched `ignoreErrors` pattern, for
instance — as entries in a top-level `errors` array. Whitespace-only entries
became findings with an empty message. They are skipped now. If one of those empty
findings was in your baseline, re-generate it: see
[Re-baselining after an upgrade](#re-baselining-after-an-upgrade).

---

## Upgrading to 0.8.0 from 0.7.x

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

Two releases were tagged `v1.0.0` and `v1.1.0` in September 2026, then the
package was renumbered onto the `0.x` line starting at `v0.2` and developed
there up to `v0.9.0`. The `1.x` line resumed at `v1.2.0` (October 2026).

**`v1.0.0` and `v1.1.0` are not part of the release sequence.** Their API is
not the `1.2.0+` API. If you pinned `^1.0` or `^1.1` back then, Composer will
now resolve `1.2.0` or later, which is the intended target — re-baseline and
read the `1.2.0` entry above. The changelog entry that describes the
renumbering is kept in
[CHANGELOG.md](CHANGELOG.md#110--100---2026-09-24-superseded).

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