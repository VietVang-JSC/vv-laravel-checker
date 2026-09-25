# Spec — Precision Wave 2: 3 new analyzer families

> Goal: go deeper on **static precision** (the area Enlightn gave up on) — add 3
> Laravel-specific rule families, each with a TP/FP corpus so precision/recall
> never regress. See `docs/comparison-enlightn.md` §4.

## 1. Assignment (3 parallel agents)

| Agent | Rule | Rule ID | Config key | Severity / Confidence |
|---|---|---|---|---|
| A | Open Redirect | `OWASP_OPEN_REDIRECT` | `owasp.open_redirect` | Error / High |
| B | Path Traversal | `OWASP_PATH_TRAVERSAL` | `owasp.path_traversal` | Error / High |
| C | Blade unescaped echo XSS | `OWASP_BLADE_XSS` | `owasp.blade_xss` | Error / High |

## 2. Per-rule semantics (mandatory)

### Agent A — Open Redirect (`src/Analyzers/Owasp/OwaspOpenRedirectAnalyzer.php`)

Flag when the redirect target is not a literal and cannot be proven safe:

- Sinks: `redirect($target)`, `redirect()->away($t)`, `redirect()->to($t)`,
  `Redirect::away($t)`, `Redirect::to($t)`, `Redirect::route(...)` — do NOT flag
  (`route()` is safe by definition), `back()` / `redirect()->back()` — do NOT flag.
- Safe (skip): string literal, `route(...)` / `back()` / `url()->previous()` calls,
  `config()` / `env()` lookups.
- Flag: Variable, PropertyFetch, MethodCall, other FuncCalls, Concat/Interpolation
  (unless every leaf is safe per the definition above).
- Sample TP: `return redirect($request->input('next'));`
- Sample FPs (must stay silent): `return redirect()->route('home');`,
  `return redirect(config('app.url') . '/done');`

### Agent B — Path Traversal (`src/Analyzers/Owasp/OwaspPathTraversalAnalyzer.php`)

Flag when a file sink receives a tainted path without going through `basename()`:

- Sinks (arg 0): `file_get_contents`, `file_put_contents`, `fopen`, `file`,
  `readfile`, `include`/`require`/`include_once`/`require_once` with a dynamic expr,
  `Storage::get/put/delete/download`, `response()->download/file`.
- Safe (skip): string literal, `basename(...)`-wrapped expr, `storage_path()`/
  `base_path()` with all-literal args, `env()/config()` (deploy-time).
- Flag: Variable, PropertyFetch, MethodCall, Concat/Interpolation containing a dynamic part.
- Sample TP: `return response()->download(storage_path('docs/' . $request->file));`
  (no `basename()` → correctly flagged).
- Sample FPs (must stay silent): `file_get_contents(storage_path('app/' . basename($name)));`

### Agent C — Blade XSS (`src/Analyzers/Owasp/OwaspBladeXssAnalyzer.php`)

Flag `{!! ... !!}` containing dynamic data in `.blade.php` files:

- Override `supports()` to accept `*.blade.php` (do NOT modify `collectFiles` —
  that is the integrator's job).
- Flag any `{!!` block containing the `$` character (a variable) or `request(`.
- Skip blocks without `$` (e.g. `{!! csrf_field() !!}` — pure function call)
  and blocks containing `e(` (manually escaped).
- Use a regex/tokenizer over the raw content (blade is not valid PHP,
  do NOT use PHP-Parser for this file).
- Sample TP: `<div>{!! $comment->body !!}</div>`
- Sample FPs (must stay silent): `{!! csrf_field() !!}`, `{{ $name }}` (escaped syntax).

## 3. Shared conventions (mandatory for all 3)

- Namespace/file follow the `OwaspXxeAnalyzer` pattern; class is `final`, `extends AbstractAnalyzer`
  (agent C still extends but overrides `supports()`).
- Class docblock clearly states Assumes + "Deliberately not flagged".
- Report issues via `$this->makeIssue(RULE, msg, $file, $line, Severity::Error, ['sink' => ...])`.
- Full types for phpstan level 6 (see `OwaspSsrfAnalyzer` as an example).
- PSR-12 (run `vendor/bin/phpcs` on the new files before finishing).

## 4. File boundaries (ANTI-CONFLICT — follow strictly)

- Each agent MAY ONLY CREATE 2 new files (names in §2 + `tests/Unit/<Rule>AnalyzerTest.php`,
  e.g. `tests/Unit/OwaspOpenRedirectAnalyzerTest.php`, ≥ 6 TP/FP tests).
- **FORBIDDEN** to modify shared files: `CustomAnalyzerChecker.php`, `config/*`,
  `AnalyzerMetricsTest.php`, `docs/*`, `CHANGELOG.md`, `README.md`.
- Verify with `vendor/bin/phpunit --filter <YourTestName> --do-not-cache-result`
  (do NOT run full `composer check` to avoid cache clashes between agents).
- When done, return exactly 5 items: (1) rule summary, (2) the
  `entry(...)` wiring line for `buildAnalyzers()`, (3) the config line for the `owasp` section,
  (4) 4+ corpus cases in `AnalyzerMetricsTest::corpus()`
  format (string content uses double quotes with `\$` escaping), (5) 1 docs paragraph for
  `docs/false-positives.md` + 1 CHANGELOG line.

## 5. Integration (done later by the integrator, not the agents' job)

Wire checker + config + corpus + docs + `collectFiles` supporting `*.blade.php`
+ full `composer check` + pilot re-scan for FPs + commit + push.
