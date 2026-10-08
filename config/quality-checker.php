<?php

return [
    'paths' => ['app', 'routes', 'database', 'config', 'tests'],

    // Checkers to skip, e.g. ['phpstan', 'composer_audit']. Merged with
    // --exclude, so neither source overrides the other. Paths to skip go in
    // analyzers.exclude_paths below, not here.
    'exclude' => [],

    // Self-provision missing tools: phpcs/phpstan/phpunit via composer, trivy
    // via a cached binary download. Off by default: this runs `composer require
    // --dev` inside your project, which edits composer.json and vendor/ before
    // you have seen a single finding, and there is no undo. Turn it on once you
    // have decided you want it. Disable for air-gapped/read-only projects.
    'auto_install_tools' => false,

    // Gate tier. 'security' fails only on security issues (high confidence);
    // 'quality' and 'all' add the phpcs/phpstan/phpunit errors. Checkers that
    // produce no quality-gate signal (dependency audit, trivy, the heuristic
    // analyzers) report the same in all three tiers — use 'exclude' or
    // --only to skip them.
    'tier' => 'quality',

    // Minimum confidence to report. Heuristics below this are hidden.
    'min_confidence' => 'low',

    'phpcs' => [
        'standard' => 'PSR12',
        'severity' => 0,
    ],

    'phpstan' => [
        'level' => 5,
        'memoryLimit' => '1G',
    ],

    'phpunit' => [
        'testsuite' => null,
        'coverageThreshold' => 60,
    ],

    'composer_audit' => [
        'enabled' => true,
    ],

    'trivy' => [
        'enabled' => false,
        'mode' => 'config',
        'binary' => 'trivy',
        'version' => '0.74.0',
    ],

    // Result cache for checker runs (file-based under the output directory).
    'cache' => [
        'enabled' => true,
        'ttl' => 3600,
    ],

    'analyzers' => [
        'enabled' => true,

        // Inline per-finding suppression via `// quality-checker-ignore RULE`
        // (same line) or `// quality-checker-ignore-next-line RULE`.
        'inline_suppression' => true,

        // Security rules (high/medium confidence) — on by default.
        'security' => [
            'sql_injection' => true,
            'unsafe_eval' => true,
            'hardcoded_secret' => true,
            'mass_assignment' => true,
            'unsafe_unserialize' => true,
            'insecure_hash' => true,
            // Programmatic cookies without an explicit Secure flag.
            'insecure_cookie' => true,
            // Login without session rotation + weak password length floors.
            'auth_hardening' => true,
            'laravel_taint' => true,
            'disabled_csrf' => true,
            'taint_engine' => false,
        ],

        // OWASP Top 10 (2023) API mapping — high confidence.
        'owasp' => [
            'broken_access_control' => true,
            // Resolve route-middleware authorization (Route::middleware('can:...'),
            // groups) so actions protected outside the controller are not flagged.
            'route_middleware' => true,
            'blade_xss' => true,
            'open_redirect' => true,
            'path_traversal' => true,
            'ssrf' => true,
            'ssti' => true,
            'misconfiguration' => true,
            'command_injection' => true,
            'xxe' => true,
            // v0.6.1 object-level authorization (IDOR) — shadow + v0.6.2
            // production mapping. Records OwnershipDecision chains
            // (sidecar) and emits conservative REVIEW/EXPOSED findings
            // with full provenance; UNKNOWN/PROTECTED never emit.
            'ownership_idor' => true,
        ],

        // Laravel-specific code quality — medium confidence.
        'laravel' => [
            'migration' => true,
            'route_validation' => true,
        ],

        // Test-coverage heuristics.
        'test_coverage' => [
            // Unified missing-test detector (controller/service/repository/model, unit+feature).
            'unified' => true,
            // Other heuristic rules stay opt-in (off) to avoid noise.
            'missing_controller_test' => false,
            'missing_service_test' => false,
            'missing_model_test' => false,
            'missing_feature_coverage' => false,
            'test_without_assert' => false,
        ],

        // Convention heuristics — low confidence, off by default (opt-in).
        'convention' => [
            'naming_convention' => false,
            'todo_fixme' => false,
            'dead_code' => false,
            'laravel_pitfall' => false,
        ],

        // Frontend heuristics — JS/CSS/Blade stack.
        // js_syntax/css_syntax are Warning/Medium (likely typo, not security gate);
        // blade_stack orphan push is Warning, empty stack is Info, unclosed block is Error.
        'frontend' => [
            'js_syntax' => true,
            'css_syntax' => true,
            'blade_stack' => true,
        ],

        // Eloquent model directories for mass-assignment resolution.
        'models_dirs' => ['app/Models'],

        // Additional protective middleware name fragments for access control.
        'extra_middleware' => [],

        // Additional safe-output function needles for Blade XSS (e.g. 'my_escape(', 'MyLib::').
        'extra_sanitizers' => [],

        // Per-rule severity remapping, applied after analysis.
        //
        // `OWASP_BLADE_DYNAMIC_INCLUDE` is the one Blade rule demoted by default. It
        // reports every dynamic view name (`@include($view)`, `@extends('a.' . $x)`)
        // at `error`, because Blade has no data-flow analysis and so cannot tell a
        // user-steerable template name from a fixed one built at runtime. Across the
        // 27-project benchmark the Blade findings were dominated by this rule, and
        // at `error` a default run came out red before the user had seen anything.
        // Demoting it to `info` keeps the findings visible in the report without
        // failing a build on something that is usually not exploitable.
        //
        // `OWASP_BLADE_XSS` is deliberately NOT demoted. Its `error` severity fires
        // only for request-derived output — `{!! request('q') !!}` and the
        // superglobals — which is reflected XSS and is the one Blade finding that
        // genuinely deserves to fail. Its ordinary `{!! $model->field !!}` hits are
        // already `warning` and never tripped the gate, so demoting the rule would
        // have cost reflected-XSS coverage without fixing the noise. If your team
        // treats every dynamic view name as a finding worth blocking, set this rule
        // back to 'error' instead of relying on the analyzer's own severity.
        'severity_overrides' => [
            'OWASP_BLADE_DYNAMIC_INCLUDE' => 'info',
        ],

        // Skip PHP files larger than this (multi-MB data dumps exhaust the
        // parser with no signal). 0 or negative disables the limit.
        'max_file_kb' => 1024,

        // Paths the custom analyzers never look at. `analyzers.exclude` above
        // filters checker names, not files, so this is the only way to keep the
        // analyzers out of a directory. Fixtures are excluded by default: code
        // under a `fixtures/` directory exists to be vulnerable (test samples,
        // security demos), and reporting it is noise, not signal. Accepts globs
        // (`*/fixtures/*`, matched against the whole path) or plain segment
        // sequences (`tests/fixtures`, matched on `/` boundaries), both
        // case-insensitive. Matching files are counted in the checker summary, so
        // nothing is hidden silently. Override freely: `[]` scans everything.
        'exclude_paths' => ['*/fixtures/*'],
    ],

    'fail_on' => 'error',

    // Quality gate: rules listed here never fail the gate and are hidden
    // from reports (e.g. ['MISSING_MODEL_TEST']). Same as --ignore=.
    'quality_gate' => [
        'ignore' => [],
    ],

    'output_dir' => 'reports/quality-checker',

    // HTML report extras. Set repo_url after publishing (or via
    // config/quality-checker.php) to get GitHub blob links; otherwise the
    // report uses vscode:// deep links.
    'html' => [
        'repo_url' => null, // e.g. https://github.com/org/repo
        'branch' => 'main',
        // Context lines rendered around each finding (0 = disable snippets).
        'code_context' => 3,
    ],
];
