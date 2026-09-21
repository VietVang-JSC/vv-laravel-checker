# Contributing

Thanks for helping improve `vietvang/quality-checker`! This guide covers local
setup, running the checks, and how to add a new analyzer.

## Requirements

- PHP `^8.1`
- [Composer](https://getcomposer.org/)

## Setup

```bash
composer install
```

This installs the package and its dev dependencies (PHPUnit, PHPStan, PHP_CodeSniffer, Orchestra Testbench).

## Running checks

The package checks its own codebase with the same toolchain it exposes to users:

```bash
composer check
```

`composer check` is a shortcut that runs, in order:

| Command         | What it runs                                          |
|-----------------|-------------------------------------------------------|
| `composer lint` | PHP_CodeSniffer, `PSR12` standard, against `src` and `tests` |
| `composer analyse` | PHPStan at `level 6` against `src` and `tests`        |
| `composer test` | PHPUnit (all unit and feature tests)                  |

You can run each step individually as well. `composer test` (PHPUnit) accepts
the usual flags, e.g. `composer test -- --filter=SomeTest`.

## Adding a new analyzer

Analyzers inspect PHP source with `nikic/php-parser` and emit `Issue` objects.

1. **Create the analyzer class** under `src/Analyzers/` (e.g. `src/Analyzers/Security/`),
   extending `VietVang\QualityChecker\Analyzers\AbstractAnalyzer`:

   ```php
   <?php

   declare(strict_types=1);

   namespace VietVang\QualityChecker\Analyzers\Security;

   use VietVang\QualityChecker\Analyzers\AbstractAnalyzer;
   use VietVang\QualityChecker\Result\Confidence;
   use VietVang\QualityChecker\Result\Issue;
   use VietVang\QualityChecker\Result\Severity;

   final class ExampleAnalyzer extends AbstractAnalyzer
   {
       private const RULE = 'EXAMPLE';

       /**
        * @param list<string> $files
        * @return Issue[]
        */
       public function analyze(array $files): array
       {
           // walk $files, parse with $this->parse($code), inspect with $this->finder(),
           // and return issues built via $this->makeIssue(...).
           return [];
       }
   }
   ```

   Use `AbstractAnalyzer::makeIssue()` and pass an explicit `Severity` and
   `Confidence` (or accept the `High` default). The deduplicator and the
   `min_confidence` filter run automatically, so choose confidence honestly.

2. **Register the analyzer** in `src/Checkers/CustomAnalyzerChecker.php`, inside
   `buildAnalyzers()`, using a `group.rule` config key:

   ```php
   $this->entry($analyzers, 'security.example', new ExampleAnalyzer()),
   ```

3. **Add the config key** in `config/quality-checker.php` under the matching
   `analyzers` group, defaulting to `false` for opt-in heuristics:

   ```php
   'security' => [
       'example' => true,
       // ...
   ],
   ```

4. **Write tests** for the new rule under `tests/` (see below).

## Testing conventions

- New rules **must** ship with tests: unit tests for the analyzer logic and,
  where a rule produces a reportable `Issue`, a fixture file under
  `tests/Feature/fixtures/` plus an assertion in
  `tests/Feature/QualityCheckCommandTest.php`.
- Keep tests fast: prefer unit tests that call `analyze()` on a fixture array of
  file paths.

## Pull request conventions

- Follow **PSR-12**.
- Every PHP file starts with `declare(strict_types=1);`.
- Keep changes focused; add or update the relevant section in `CHANGELOG.md`
  under `[Unreleased]`.
- Run `composer check` locally and make sure it passes before opening a PR.
- Do not include unrelated refactors or dependency bumps.

## Reporting bugs

- Open an issue describing the expected vs. actual behaviour, the PHP version,
  the Laravel version, and a minimal reproduction snippet.
- If the bug is a false positive in an analyzer, include the offending source
  file and the reported rule id.
