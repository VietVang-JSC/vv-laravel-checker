<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Result;

/**
 * Single registry of every rule id the custom analyzers can emit, plus the
 * OWASP-2021 category each one rolls up into.
 *
 * Rule ids used to be `private const` inside each analyzer and re-typed as bare
 * strings in four or five downstream places (remediation catalog, JSON
 * reporter, quality score, SARIF tags). Nothing tied those copies together, so
 * adding a rule meant remembering four edits — and forgetting one silently
 * dropped the rule from a report. `OWASP_BLADE_DYNAMIC_INCLUDE` and
 * `OWASP_OWNERSHIP_IDOR` were both shipped that way: they had no OWASP mapping,
 * so `JsonReporter::buildOwasp()` skipped them and the JSON `owasp.total`
 * under-reported real findings.
 *
 * Analyzers keep their own constants (they are the definition); this class is
 * the single place reporters, the remediation catalog and the tests agree on.
 * `RuleIdsTest` reflects over the analyzer constants and fails if the two ever
 * drift, so the mapping cannot rot again.
 */
final class RuleIds
{
    // --- Security analyzers -------------------------------------------------
    public const SQL_INJECTION = 'SQL_INJECTION';
    public const UNSAFE_EVAL = 'UNSAFE_EVAL';
    public const HARDCODED_SECRET = 'HARDCODED_SECRET';
    public const MASS_ASSIGNMENT = 'MASS_ASSIGNMENT';
    public const UNSAFE_UNSERIALIZE = 'UNSAFE_UNSERIALIZE';
    public const INSECURE_HASH = 'INSECURE_HASH';
    public const INSECURE_COOKIE = 'INSECURE_COOKIE';
    public const SESSION_FIXATION = 'SESSION_FIXATION';
    public const WEAK_PASSWORD_POLICY = 'WEAK_PASSWORD_POLICY';
    public const LARAVEL_TAINT = 'LARAVEL_TAINT';
    public const DISABLED_CSRF_AUTHORIZE_TRUE = 'DISABLED_CSRF_AUTHORIZE_TRUE';
    public const DISABLED_CSRF_EXCEPTION_STAR = 'DISABLED_CSRF_EXCEPTION_STAR';

    // --- Optional taint engine (off by default) -----------------------------
    public const TAINT_SQL_INJECTION = 'TAINT_SQL_INJECTION';
    public const TAINT_COMMAND_INJECTION = 'TAINT_COMMAND_INJECTION';
    public const TAINT_EVAL = 'TAINT_EVAL';
    public const TAINT_UNSAFE_SERIALIZE = 'TAINT_UNSAFE_SERIALIZE';

    // --- OWASP analyzers ----------------------------------------------------
    public const OWASP_BROKEN_ACCESS_CONTROL = 'OWASP_BROKEN_ACCESS_CONTROL';
    public const OWASP_OWNERSHIP_IDOR = 'OWASP_OWNERSHIP_IDOR';
    public const OWASP_PATH_TRAVERSAL = 'OWASP_PATH_TRAVERSAL';
    public const OWASP_BLADE_DYNAMIC_INCLUDE = 'OWASP_BLADE_DYNAMIC_INCLUDE';
    public const OWASP_OPEN_REDIRECT = 'OWASP_OPEN_REDIRECT';
    public const OWASP_SSRF = 'OWASP_SSRF';
    public const OWASP_SSTI = 'OWASP_SSTI';
    public const OWASP_COMMAND_INJECTION = 'OWASP_COMMAND_INJECTION';
    public const OWASP_BLADE_XSS = 'OWASP_BLADE_XSS';
    public const OWASP_MISCONFIGURATION = 'OWASP_MISCONFIGURATION';
    public const OWASP_XXE = 'OWASP_XXE';

    // --- Laravel quality analyzers -----------------------------------------
    public const MIGRATION_MISSING_DOWN = 'MIGRATION_MISSING_DOWN';
    public const MIGRATION_DESTRUCTIVE_UP = 'MIGRATION_DESTRUCTIVE_UP';
    public const ROUTE_MISSING_VALIDATION = 'ROUTE_MISSING_VALIDATION';

    // --- Test coverage analyzers -------------------------------------------
    public const MISSING_CONTROLLER_TEST = 'MISSING_CONTROLLER_TEST';
    public const MISSING_SERVICE_TEST = 'MISSING_SERVICE_TEST';
    public const MISSING_REPOSITORY_TEST = 'MISSING_REPOSITORY_TEST';
    public const MISSING_MODEL_TEST = 'MISSING_MODEL_TEST';
    public const MISSING_UNIT_TEST = 'MISSING_UNIT_TEST';
    public const MISSING_FEATURE_COVERAGE = 'MISSING_FEATURE_COVERAGE';
    public const TEST_WITHOUT_ASSERT = 'TEST_WITHOUT_ASSERT';

    // --- Convention analyzers (default off) ---------------------------------
    public const DEAD_CODE = 'DEAD_CODE';
    public const NAMING_CONVENTION = 'NAMING_CONVENTION';
    public const TODO_FIXME = 'TODO_FIXME';
    public const LARAVEL_PITFALL_ENV_OUTSIDE_CONFIG = 'LARAVEL_PITFALL_ENV_OUTSIDE_CONFIG';
    public const LARAVEL_PITFALL_DEBUG = 'LARAVEL_PITFALL_DEBUG';
    public const LARAVEL_PITFALL_SLEEP_IN_TEST = 'LARAVEL_PITFALL_SLEEP_IN_TEST';

    /**
     * Every rule id a custom analyzer can emit, in report order.
     *
     * @return list<string>
     */
    public static function all(): array
    {
        return self::$all ??= array_merge(array_keys(self::owaspCategories()), [
            self::SQL_INJECTION,
            self::UNSAFE_EVAL,
            self::HARDCODED_SECRET,
            self::MASS_ASSIGNMENT,
            self::UNSAFE_UNSERIALIZE,
            self::INSECURE_HASH,
            self::INSECURE_COOKIE,
            self::SESSION_FIXATION,
            self::WEAK_PASSWORD_POLICY,
            self::LARAVEL_TAINT,
            self::DISABLED_CSRF_AUTHORIZE_TRUE,
            self::DISABLED_CSRF_EXCEPTION_STAR,
            self::TAINT_SQL_INJECTION,
            self::TAINT_COMMAND_INJECTION,
            self::TAINT_EVAL,
            self::TAINT_UNSAFE_SERIALIZE,
            self::MIGRATION_MISSING_DOWN,
            self::MIGRATION_DESTRUCTIVE_UP,
            self::ROUTE_MISSING_VALIDATION,
            self::MISSING_CONTROLLER_TEST,
            self::MISSING_SERVICE_TEST,
            self::MISSING_REPOSITORY_TEST,
            self::MISSING_MODEL_TEST,
            self::MISSING_UNIT_TEST,
            self::MISSING_FEATURE_COVERAGE,
            self::TEST_WITHOUT_ASSERT,
            self::DEAD_CODE,
            self::NAMING_CONVENTION,
            self::TODO_FIXME,
            self::LARAVEL_PITFALL_ENV_OUTSIDE_CONFIG,
            self::LARAVEL_PITFALL_DEBUG,
            self::LARAVEL_PITFALL_SLEEP_IN_TEST,
        ]);
    }

    /** @var list<string>|null */
    private static ?array $all = null;

    /** @var array<string, string>|null */
    private static ?array $owaspCategories = null;

    /**
     * OWASP-2021 category per OWASP rule id.
     *
     * The ids follow the OWASP Top 10 **2021** edition — the edition this
     * mapping encodes. The 2025 revision reorders and renames categories, but
     * rule ids here are stable, so adopting it is a data change in this map
     * rather than a rename across the analyzers. `RuleIdsTest` requires every
     * `OWASP_*` rule to appear here, and `RuleDocsTest` requires the README rule
     * tables to document the same category.
     *
     * Memoised: `owaspCategory()` / `isOwasp()` run per issue while reporters
     * render, so rebuilding the map each time would be wasteful.
     *
     * @return array<string, string>
     */
    public static function owaspCategories(): array
    {
        return self::$owaspCategories ??= [
            self::OWASP_BROKEN_ACCESS_CONTROL => 'A01 Broken Access Control',
            self::OWASP_OWNERSHIP_IDOR => 'A01 Broken Access Control',
            self::OWASP_PATH_TRAVERSAL => 'A01 Path Traversal',
            self::OWASP_BLADE_DYNAMIC_INCLUDE => 'A01 Path Traversal',
            self::OWASP_BLADE_XSS => 'A03 Injection (XSS)',
            self::OWASP_SSTI => 'A03 Injection (SSTI)',
            self::OWASP_COMMAND_INJECTION => 'A03 Injection (Command)',
            self::OWASP_MISCONFIGURATION => 'A05 Security Misconfiguration',
            self::OWASP_XXE => 'A05 XXE',
            self::OWASP_OPEN_REDIRECT => 'A07 Open Redirect',
            self::OWASP_SSRF => 'A10 SSRF',
        ];
    }

    /**
     * @return list<string>
     */
    public static function owaspRules(): array
    {
        return array_keys(self::owaspCategories());
    }

    /**
     * Prefix-based on purpose: SARIF tagging and the per-rule OWASP grouping
     * must keep labelling any `OWASP_*` finding, including one a future
     * analyzer emits before it is added to the category map. Only the
     * category rollup needs the registry, and an unmapped rule there is
     * exactly what RuleIdsTest guards against.
     */
    public static function isOwasp(string $rule): bool
    {
        return str_starts_with($rule, 'OWASP_');
    }

    public static function owaspCategory(string $rule): ?string
    {
        $categories = self::owaspCategories();

        return $categories[$rule] ?? null;
    }
}
