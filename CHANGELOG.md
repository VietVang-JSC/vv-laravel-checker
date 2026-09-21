# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- OWASP Top-10 (2023) analyzers: broken access control, SSRF, SSTI, misconfiguration, command injection, XXE.
- Confidence model (`low` / `medium` / `high`) with quality tiers (`security` / `quality` / `all`) and `min_confidence` filtering.
- Deduplicator for issues generated from multiple analyzers.
- Migration and route-validation analyzers for Laravel-specific code quality.
- PHPUnit coverage threshold enforcement.
- Dogfooding tools: the package now checks its own codebase (phpcs + phpstan + phpunit).
- GitHub Actions CI and dogfooding workflows for `8.1` / `8.2` / `8.3`.
- Console, JSON, Markdown and HTML reporters.
- Auto-provisioning of missing tools: composer-based tools (phpcs/phpstan/phpunit) installed via `composer require --dev` in the target project, and the Trivy binary auto-downloaded into a per-user cache. Disable with `--no-auto-install` / `auto_install_tools => false`.
- Checkers fall back to the package's own `vendor/bin` when a tool is missing but bundled.
- Unified test-coverage detector (`test_coverage.unified`, on by default) that flags source classes
  (controller / service / repository / model) with no matching test, scanning both `tests/Unit` and
  `tests/Feature` from the passed file set.
- Reports now group issues by rule (`Top Rules`) across JSON / Markdown / HTML / console via `IssueGrouper`.
- Expanded test suite to **121 tests** covering every security + OWASP analyzer (positive/negative),
  edge cases (empty project, crash tool, invalid PHP, Windows paths), baseline, cache, parallel runner.
- Code coverage measurement via PCOV/Xdebug in CI (~53% line coverage, core at 100%).

### Changed

- `HtmlReporter` rewritten as a programmatic HTML builder: the Blade-subset template compiler that used `eval()` and `extract()` was removed entirely.
- All user-controlled data in the HTML report is escaped with `htmlspecialchars(..., ENT_QUOTES, 'UTF-8')`.
- Composer audit runs non-interactive with a shorter timeout and reports `error` (instead of `passed`) when the command itself fails (e.g. offline / rate-limited).

### Fixed

- Removed dead code in `TaintEngine` that never reported tainted return values.
- `MassAssignmentAnalyzer` incorrectly calling `getArgs()` on non-call nodes.
- XXE analyzer using a missing `end()` constant reference.
- `HtmlReporter` Blade compiler issues (`@else`, stray `makeView` closure, template branch).
- PHPUnit JUnit report double-counting tests.
- PHPStan project configuration not resolving against the correct baseline.
- Checker exit-code detection not honouring `fail_on` TIER levels.
- `TrivyChecker` reading its own defaults instead of the `trivy.*` config from the context, so `trivy.enabled` was ignored.
- Trivy release asset naming (`windows-64bit`) and default version (`0.74.0`).

## [0.1.0] - 2026-09-20

### Added

- Laravel artisan command `quality:check` with a quality gate over phpcs, phpstan, phpunit, composer audit and custom PHP-Parser analyzers.
- Security analyzers for SQL injection, unsafe eval, hardcoded secrets, mass assignment, unsafe deserialization, insecure hashing, Laravel taint and disabled CSRF.
- Test-coverage heuristics (missing controller / service / model tests, missing feature coverage, tests without assertions).
- Convention heuristics (naming conventions, TODO/FIXME, dead code, Laravel pitfalls).
- Baseline generation and filtering, JSON / Markdown / console reporters, exit codes and `--fail-on` control.
- Configuration via `config/quality-checker.php`.

[0.1.0]: https://github.com/your-org/quality-checker/releases/tag/0.1.0