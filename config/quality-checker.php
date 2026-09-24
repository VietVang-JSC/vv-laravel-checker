<?php

return [
    'paths' => ['app', 'routes', 'database', 'config', 'tests'],

    'exclude' => [],

    // Self-provision missing tools: phpcs/phpstan/phpunit via composer, trivy
    // via a cached binary download. Disable for air-gapped/read-only projects.
    'auto_install_tools' => true,

    // Quality gate tier. 'security' only fails on high-confidence security issues;
    // 'quality' adds phpcs/phpstan/phpunit errors; 'all' surfaces every heuristic.
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

    'analyzers' => [
        'enabled' => true,

        // Security rules (high/medium confidence) — on by default.
        'security' => [
            'sql_injection' => true,
            'unsafe_eval' => true,
            'hardcoded_secret' => true,
            'mass_assignment' => true,
            'unsafe_unserialize' => true,
            'insecure_hash' => true,
            'laravel_taint' => true,
            'disabled_csrf' => true,
            'taint_engine' => false,
        ],

        // OWASP Top 10 (2023) API mapping — high confidence.
        'owasp' => [
            'broken_access_control' => true,
            'ssrf' => true,
            'ssti' => true,
            'misconfiguration' => true,
            'command_injection' => true,
            'xxe' => true,
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
    ],

    'fail_on' => 'error',

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
