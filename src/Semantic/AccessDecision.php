<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Semantic;

/**
 * One access-control verdict for a controller action in the context of
 * a single route. Four states — never a bare boolean:
 *
 * - PROTECTED: authorization evidence exists (ability middleware,
 *   local authorize()/Gate/FormRequest checks). No finding.
 * - REVIEW: the route authenticates (or gates) but nothing proves
 *   authorization. Finding with medium confidence.
 * - EXPOSED: public route and no local authorization evidence.
 *   Finding with high confidence.
 * - UNKNOWN: the action resolves to no route at all — keep the legacy
 *   fail-safe finding (high confidence), never a silent SAFE.
 *
 * The full middleware stack and the citing route travel with the
 * verdict so reports can explain the finding instead of asserting it.
 */
final class AccessDecision
{
    public const PROTECTED = 'protected';

    public const REVIEW = 'review';

    public const EXPOSED = 'exposed';

    public const UNKNOWN = 'unknown';

    /**
     * @param array{methods: list<string>, uri: string|null, file: string, line: int|null}|null $route
     * @param list<string> $middleware full inherited stack, outermost first
     * @param list<string|array<string, string|null>> $authorizationEvidence ability
     *   middleware and middleware evidence backing a PROTECTED verdict
     * @param list<array{alias: string, class: string|null, method: string|null, source: string|null, mechanism: string}> $middlewareResolution
     *   resolved-but-unverifiable middleware trail for REVIEW findings
     */
    public function __construct(
        public readonly string $status,
        public readonly ?array $route,
        public readonly array $middleware,
        public readonly array $authorizationEvidence,
        public readonly array $middlewareResolution = [],
    ) {
    }
}
