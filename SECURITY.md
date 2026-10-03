# Security Policy

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Report it privately through GitHub's advisory form:
<https://github.com/VietVang-JSC/vv-laravel-checker/security/advisories/new>

Include:

- affected version (`composer show rampart/quality-checker`),
- PHP and Laravel versions,
- a minimal reproduction: the PHP snippet (or project layout) plus the exact
  command you ran and the finding you got,
- what an attacker gains, and whether you already know of exploitation.

### What to expect

| Stage | Target |
|---|---|
| Acknowledgement | 3 business days |
| Triage (valid / invalid / duplicate) | 10 business days |
| Fix or mitigation plan for confirmed issues | 30 days from triage |
| Public advisory | On release, with credit to the reporter unless you opt out |

A report is a valid vulnerability when it lets someone who should not have
access do something they should not be able to do, or makes the analyzer itself
unsafe to run (for example, executing code from a scanned target, or writing
outside the configured output directory).

The following are **not** vulnerabilities:

- **A false positive.** A rule that fires on safe code is a detection-quality
  issue, not a security hole. Report it as an issue; see
  [docs/false-positives.md](docs/false-positives.md).
- **A false negative in a heuristic analyzer.** The custom analyzers are
  documented as heuristics, not verifiers, and make no completeness claim.
- **Findings in your own code that you can already see.** The tool reports what
  is in your repository, not what an outsider can reach.
- **Running the analyzer against a project you do not own.**

## Scope

**In scope**

| Component | Why |
|---|---|
| `src/` | The package itself. |
| `bin/quality-check` | Same. |
| The bundled tool installers | `auto_install_tools` downloads and executes `phpcs`/`phpstan`/`phpunit`/`trivy` — a hijacked download path would be remote code execution. |
| `vendor/` handling | Anything that resolves, executes or copies third-party code. |

**Out of scope**

| Component | Why |
|---|---|
| Findings in a scanned target project | Those are the tool working as designed. |
| Trivy findings | Third-party scanner output; report upstream. |
| CVEs in dev dependencies | `composer audit` covers this; report to the advisory database. |
| Denial of service from very large inputs | We accept that scanning a repository consumes resources proportional to its size, and we do not treat it as a vulnerability. |

## Hardening notes for operators

- Run the quality gate on an untrusted repository as an unprivileged user with
  no production credentials. The analyzers parse PHP; they do not execute it,
  but the optional `phpunit` checker runs the target's own test suite.
- `auto_install_tools` executes downloaded binaries. Disable it with
  `--no-auto-install` (or `auto_install_tools => false`) in locked-down
  environments and pre-install the tools from your own mirror.
- The taint engine (`analyzers.security.taint_engine`) is off by default; it is
  slower and has no security cost, only compute cost.
- Reports contain your file paths and source snippets. If a report leaves your
  machine, treat it as source code.

## Supported versions

This package is on the `0.x` line. Security fixes land on the latest minor
release only.

| Version | Supported |
|---|---|
| `0.7.x` | Yes |
| `0.6.x` | Security fixes on request, until `0.7.x` is superseded |
| `< 0.6` | No |