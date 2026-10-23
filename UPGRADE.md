# Upgrade guide

Breaking changes per release, newest first. This package is on the `0.x` line,
so anything that changes behaviour is called out here rather than hidden in the
[CHANGELOG](CHANGELOG.md).

Run the version you are coming from, read the entries between it and your target,
then re-baseline (below) — every behavioural change here moves findings, so a
stale baseline is how upgrades silently pass.

---

## Upgrading to 1.5.7 from 1.5.6 and earlier

### Test-coverage checks are now opt-in

`test_coverage.unified` defaults to `false` (was `true`), so missing-test
findings disappear from default scans. If your workflow reviews test gaps in
these reports, opt back in:

```php
// config/quality-checker.php
'analyzers' => [
    'test_coverage' => ['unified' => true],
],
```

or per run via a temporary config overlay. No re-baseline needed — this change
only removes findings, and baselines ignore already-absent signatures safely.

## Upgrading to 1.5.x from 1.4.x

### New default-on checks (Ops + supply chain)

**New findings may fail a previously green gate.** `1.5.0` enables by default:
`PERMS_TOO_OPEN` (world-writable `.env`/`storage`), `EOL_COMPONENT`
(end-of-life Laravel/PHP lines), `ROGUE_PHP` (`public/*.php`), `OBFUSCATED_PHP`
(`eval(base64_decode…)`), plus the `npm_audit` checker when a `package.json`
exists. `1.5.1` rewrote `EOL_COMPONENT` from a single hardcoded date (which
flagged every Laravel project) to per-major EOL tables — findings change shape.

If you upgrade and the gate goes red on these, either fix them or re-baseline
(see below). To silence one rule without baselining:
`--ignore=PERMS_TOO_OPEN` (standalone) or `quality_gate.ignore` (config).

### Bundled phpstan default is now level 6

`config/quality-checker.php` ships `phpstan.level => 6` (was `5`) to match
the package's own dogfood level. If you published the config earlier, your
copy still says `5` — nothing changes for you until you update it. After
updating, expect new phpstan findings on the first run.

## Upgrading to 1.4.x from 1.3.x

### Corpus 400 → 500 (fewer false positives, some findings move)

The labelled corpus grew (`AnalyzerMetricsTest`: 340 TP + 160 TN, holdout 98)
and several analyzers were re-tuned for precision. Net effect is fewer false
positives, but a small number of findings change rule or disappear. Re-baseline
after upgrading so the delta is intentional, not drift.

## Upgrading to 1.3.x from 1.2.x

### Frontend checks on by default

`JS_SYNTAX_ERROR`, `CSS_SYNTAX_ERROR` and `BLADE_STACK_MISMATCH` now run on
every scan (`resources/`, `public/`; `.min.`/`vendor` skipped). Minified-build
heaviness is bounded by `max_file_kb`. If your frontend is generated and noisy,
disable per rule in `config analyzers.frontend` or `--ignore` the rule.

### Coverage gate fails the build

`PHPUNIT_LOW_COVERAGE` is now severity `error`: suites under the
`coverageThreshold` (default 60%) fail `--fail-on=error` runs. Raise coverage
or lower the threshold — do not just ignore the rule.

### `OWASP_BLADE_DYNAMIC_INCLUDE` demoted to info

Dynamic view names (`@include($view)`) report at `info` by default via
`severity_overrides` — visible in reports, never fails the gate. Reflected-XSS
findings (`OWASP_BLADE_XSS` on request data) still fail at `error`. Set the
override back to `error` if your team blocks on dynamic includes.

## Upgrading to 1.2.x from 1.1.x

### Corpus 300 → 400 (precision re-tune)

Same advice as 1.4.x: re-baseline after upgrading; expect fewer false
positives and a handful of moved findings.

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