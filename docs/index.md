# Documentation

Everything shipped with the package, and what each file is for. Start at the
[README](../README.md) — it carries installation, a 5-minute quick start, the
complete rule reference, CI recipes and troubleshooting.

## User guides

| Document | Read it when |
|---|---|
| [README](../README.md) | You are installing, configuring or wiring the gate into CI. |
| [baseline.md](baseline.md) | Your first run reports hundreds of pre-existing findings. |
| [false-positives.md](false-positives.md) | A finding looks wrong, or you need to decide between fixing, suppressing and baselining it. |
| [UPGRADE.md](../UPGRADE.md) | You are moving between versions. Read this **before** re-baselining. |
| [SECURITY.md](../SECURITY.md) | You found a vulnerability in the package, or you need to know what the tool does with untrusted input. |
| [CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md) | You are contributing or reporting conduct. |

## Internal calibration records

These are working documents, not user guidance. They exist so a decision can be
revisited with the evidence that produced it.

| Document | What it records |
|---|---|
| [spec-precision-wave2.md](spec-precision-wave2.md) | The precision/recall work that pinned the labelled corpus: which rules were tuned, against which real repositories, and what regressed. |
| [comparison-enlightn.md](comparison-enlightn.md) | Where this tool sits against `enlightn/enlightn` — a static, no-boot, Windows-capable alternative to a dynamic app-booting auditor. Not a feature matrix for shopping; the decision rationale for the design. |

## Where things are defined

| Thing | Single source of truth |
|---|---|
| Rule ids and OWASP-2021 categories | `src/Result/RuleIds.php` |
| Which rules exist | The README rule tables, enforced by `tests/Unit/RuleDocsTest.php` |
| Which rules the analyzers can emit | The analyzers' own `RULE_*` constants, enforced by `tests/Unit/RuleIdsTest.php` |
| CLI options per entry point | The README Options Reference, enforced by `tests/Unit/DocsEntryPointsTest.php` |
| Default configuration | `config/quality-checker.php` |
| Precision/recall on the labelled corpus | `tests/Unit/AnalyzerMetricsTest.php`, printed by the test run |
| Holdout (19% blind) | `AnalyzerMetricsTest::holdoutCorpus()` `crc32(id)%5==0` |
| CVE recall floor (30 injections) | `tests/Unit/CveRecallTest.php` `30/30` |
| External precision sampler | `tools/sample-findings.php` → `sample.csv` → human TP/FP |
| Inter-rater kappa | `tools/inter-rater.php` `kappa ≥0.9` |

The README rule tables and the registry are checked against each other in CI:
adding a rule without documenting it, or documenting a rule that does not exist,
fails the build. That is why there are no "phantom" rule ids in these docs.

## Contributing to the docs

- Rule tables change only when the registry changes, in the same commit.
- Anything a user must act on belongs in `UPGRADE.md`, not just the changelog.
- Run `composer check` before pushing; `RuleDocsTest` parses these files.