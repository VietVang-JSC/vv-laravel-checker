# Baseline — recording known issues

Baseline lets you "accept" existing issues so that only
**new** issues introduced later are reported. Useful when introducing quality-checker
into a project that already has many issues you do not want to fix right away.

## Usage

### 1. Generate a baseline from current results

Run the check and export JSON, then create a baseline from all existing issues:

```bash
php artisan quality:check --format=json --output=reports/quality-checker
php artisan quality:check --baseline-generate
```

The `--baseline-generate` command reads the check results and writes the baseline file (by default
`baseline.json` in the project root).

### 2. Update the baseline

When you fix some issues and want to "freeze" the new state as the baseline:

```bash
php artisan quality:check --baseline-update
```

The `--baseline-update` command overwrites the baseline with **all** current issues (every
severity level). Only use it when you are sure the current state is the desired one.

### 3. Specify a custom baseline file

```bash
php artisan quality:check --baseline-file=reports/baseline.json
```

## Baseline file

The file is plain JSON containing a list of signatures (not human-readable):

```json
{
  "generated_at": "2026-09-20T10:00:00+07:00",
  "baseline": [
    "9f2c1d8a3b7e4f5a..."
  ]
}
```

Each signature is `md5(rule|file|line|message)`. When a baseline is loaded, issues
with matching signatures are skipped in the report (but still marked
`baselined` if display is needed).

## Gitignore

Depending on your team, you can choose:

- **Do not commit the baseline** (each member creates their own):
  ```gitignore
  baseline.json
  ```
- **Commit a shared baseline** (the team shares it, synced via git): remove the line above.

By default the package recommends **committing** it so the whole team shares the same quality gate, unless
you want each person to have their own baseline.

> Note: The `--baseline-generate`, `--baseline-update`, `--baseline-file`
> flags are appended to the command during integration. If the command does not support them yet,
> check whether the installed package version already includes baseline functionality.
