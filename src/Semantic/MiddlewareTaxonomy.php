<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Semantic;

/**
 * Middleware taxonomy for access-control decisions.
 *
 * Authentication is not authorization: `auth` (and its guards), token
 * guards and identity-assurance middleware prove *who* calls, never
 * *whether* they may mutate. Only ability checks (`can:*`,
 * `permission:*`, `role:*`, explicitly configured extras) count as
 * authorization evidence. Everything else with a name that *sounds*
 * protective (`admin`, `owner`, `checkLevel`, `signed`, ...) is an
 * unverifiable gate — recorded as evidence for review, never assumed
 * to authorize. Rate limiting (`throttle`), `guest` markers and the
 * framework `web`/`api` groups carry no access meaning at all.
 */
final class MiddlewareTaxonomy
{
    public const AUTHORIZATION = 'authorization';

    public const AUTHENTICATION = 'authentication';

    public const GATE = 'gate';

    public const NONE = 'none';

    /**
     * @param list<string> $extraFragments user-configured
     *   `extra_middleware` fragments — an explicit assertion by the
     *   project owner that these middleware authorize, so they rank as
     *   authorization evidence.
     */
    public static function classify(string $middleware, array $extraFragments = []): string
    {
        $parts = explode(':', $middleware, 2);
        $base = strtolower(trim($parts[0]));
        if ($base === '') {
            return self::NONE;
        }

        // Guest markers route *away* from authenticated users: the route
        // is public by design, never protected (even `guestAdmin`, which
        // merely contains a protective-sounding word).
        if ($base === 'guest' || str_starts_with($base, 'guest')) {
            return self::NONE;
        }

        foreach ($extraFragments as $fragment) {
            if ($fragment !== '' && str_contains($base, $fragment)) {
                return self::AUTHORIZATION;
            }
        }

        // Ability checks: Laravel's `can:*` plus the de-facto standard
        // spatie/laravel-permission `permission:*` / `role:*`. The base
        // name (before ':') is compared — the parameter never matters.
        $lower = strtolower(trim($middleware));
        if (
            $base === 'can'
            || str_starts_with($lower, 'can:')
            || $base === 'permission'
            || str_starts_with($lower, 'permission:')
            || $base === 'role'
            || str_starts_with($lower, 'role:')
        ) {
            return self::AUTHORIZATION;
        }

        // Identity proofs: session guards, token guards, API-key guards,
        // OAuth, and email-verification (identity assurance stacked on
        // top of authentication — never a permission check).
        if (
            $base === 'auth'
            || str_starts_with($base, 'auth:')
            || $base === 'sanctum'
            || str_starts_with($base, 'sanctum:')
            || $base === 'jwt'
            || str_starts_with($base, 'jwt:')
            || str_starts_with($base, 'jwt.')
            || $base === 'oauth'
            || str_starts_with($base, 'oauth:')
            || $base === 'verified'
            || $base === 'apikey'
            || $base === 'api_key'
            || $base === 'api.key'
            || str_contains($base, 'api.key')
            || str_contains($base, 'api_key')
            || str_contains($base, 'apikey')
        ) {
            return self::AUTHENTICATION;
        }

        // Plumbing with no access meaning: rate limiting, framework
        // default groups, route-model binding.
        if (
            $base === 'throttle'
            || str_starts_with($base, 'throttle:')
            || $base === 'web'
            || $base === 'api'
            || $base === 'bindings'
        ) {
            return self::NONE;
        }

        // Anything else (`admin`, `owner`, `checkLevel`, `signed`, ...)
        // *sounds* protective but its implementation is unknown to the
        // engine: evidence for review, never assumed authorization.
        return self::GATE;
    }
}
