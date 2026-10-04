# Contributing

Thanks for helping improve `rampart/quality-checker`! This guide covers local
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
| `composer lint` | PHP_CodeSniffer, `PSR12` standard, against `src`, `tests` and `tools` |
| `composer analyse` | PHPStan at `level 6` against `src` and `tests`        |
| `composer test` | PHPUnit (all unit and feature tests)                  |

You can run each step individually as well. `composer test` (PHPUnit) accepts
the usual flags, e.g. `composer test -- --filter=SomeTest`.

### The smoke test

`composer check` runs from a clone, where `vendor/autoload.php` is one directory
up from `bin/` and `tests/` and `.github/` are simply present. Neither is true of
an installed package, and that gap is how a broken `vendor/bin/quality-check` and
a 19 MB archive shipped unnoticed.

```bash
composer smoke
```

It builds the real `composer archive`, asserts its contents are the runtime
subset, installs it into a throwaway project from an `artifact` repository, and
runs the *installed* binary against a planted-bad app. It needs network access
and takes a minute or two; CI runs it on Ubuntu in a job of its own. It is not
part of `composer check` because it installs from the network, which a
pre-commit hook or an offline machine should not do.

## Adding a new analyzer

Analyzers inspect PHP source with `nikic/php-parser` and emit `Issue` objects.

1. **Create the analyzer class** under `src/Analyzers/` (e.g. `src/Analyzers/Security/`),
   extending `Rampart\QualityChecker\Analyzers\AbstractAnalyzer`:

   ```php
   <?php

   declare(strict_types=1);

   namespace Rampart\QualityChecker\Analyzers\Security;

   use Rampart\QualityChecker\Analyzers\AbstractAnalyzer;
   use Rampart\QualityChecker\Result\Confidence;
   use Rampart\QualityChecker\Result\Issue;
   use Rampart\QualityChecker\Result\Severity;

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

## Remotes and releases

This repository has two remotes and both must stay in step:

| Remote | Repository | Role |
|---|---|---|
| `origin` | `VietVang-JSC/vv-laravel-checker` | The project's working repository. |
| `rampart` | `thiennhant95/Rampart` | **The distribution source Packagist tracks.** Tags here are what `composer require rampart/quality-checker` resolves. |

`remote.pushDefault` is set to `rampart`, and a local alias pushes to both:

```bash
git pushall            # pushes to origin and rampart
git pushall --tags     # pushes tags to both
```

Prefer `git pushall` over `git push`. A commit that reaches one remote but not
the other is invisible until Packagist serves a release that does not exist
locally.

### Cutting a release

```bash
composer check                                   # never tag a red build
git pushall --tags                               # if CI is green on both remotes
```

Packagist crawls the `rampart` remote, so a tag must exist **there** — a tag
pushed only to `origin` produces a release nobody can install. Publish only the
`0.x` tags: `v1.0.0` / `v1.1.0` are a dead line (see [UPGRADE.md](UPGRADE.md)) and
are deliberately absent from the distribution remote.

After tagging, confirm what Composer will actually resolve — the website's
`.json` endpoint serves a stale cache, use the p2 endpoint instead:

```bash
curl -s https://repo.packagist.org/p2/rampart/quality-checker.json | jq -r '.packages["rampart/quality-checker"][].version'
```

## Reading a red CI run

`composer check` passing locally does not mean CI passes — the matrix runs PHP
8.1 against Laravel 10, and Windows runners differ from Linux in which PHP
extensions are enabled. When CI is red, read the job log rather than guessing:

```bash
gh run list --limit 5
gh run view --log-failed
```

## Reporting bugs

- Open an issue describing the expected vs. actual behaviour, the PHP version,
  the Laravel version, and a minimal reproduction snippet.
- If the bug is a false positive in an analyzer, include the offending source
  file and the reported rule id.
