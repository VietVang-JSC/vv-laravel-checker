<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Semantic;

/**
 * One object-level authorization verdict for a controller action (v0.6.1,
 * shadow mode). Four states — never a bare boolean, never a guess:
 *
 * - PROTECTED: ownership evidence exists (relationship-scoped query,
 *   where(owner, currentUser), explicit owner comparison + deny,
 *   enforcing Policy/Gate, `can:` middleware, ownership middleware).
 *   No finding.
 * - REVIEW: the action authenticates (auth middleware or principal use)
 *   and performs a sensitive operation on a request-identified resource,
 *   but nothing proves ownership. Human review (deleteLink lives here).
 * - EXPOSED: public route (no auth) + sensitive operation on a
 *   request-identified resource. High confidence.
 * - UNKNOWN: the chain cannot be proven — dynamic lookup (service
 *   return), tenant/team multi-hop, polymorphic ownership, custom
 *   middleware, or no route at all. Never a silent SAFE.
 *
 * Auth alone is never ownership. The full chain travels with the
 * verdict so review explains instead of asserting.
 */
final class OwnershipDecision
{
    public const PROTECTED = 'protected';

    public const REVIEW = 'review';

    public const EXPOSED = 'exposed';

    public const UNKNOWN = 'unknown';

    /**
     * @param array{methods: list<string>, uri: string|null, file: string, line: int|null}|null $route
     * @param list<string> $middleware full inherited stack, outermost first
     * @param array{kind: string, detail: string}|null $identifier request-controlled id source
     * @param array{kind: string, detail: string}|null $lookup model lookup shape
     * @param array{kind: string, detail: string}|null $operation sensitive operation
     * @param array{kind: string, detail: string}|null $principal authenticated principal, if any
     * @param list<array{mechanism: string, detail: string, confidence: string}> $ownershipEvidence
     * @param list<array{mechanism: string, detail: string, confidence: string}> $authorizationEvidence
     * @param list<array{kind: string, detail: string, line: int|null}> $trace source → lookup → operation chain
     */
    public function __construct(
        public readonly string $status,
        public readonly string $controller,
        public readonly string $method,
        public readonly string $file,
        public readonly int $line,
        public readonly ?array $route,
        public readonly array $middleware,
        public readonly ?array $identifier,
        public readonly ?array $lookup,
        public readonly ?array $operation,
        public readonly ?array $principal,
        public readonly array $ownershipEvidence,
        public readonly array $authorizationEvidence,
        public readonly string $confidence,
        public readonly array $trace,
    ) {
    }

    /**
     * @return array<string, mixed> sidecar-serializable chain
     */
    public function toArray(): array
    {
        return [
            'status' => $this->status,
            'controller' => $this->controller,
            'method' => $this->method,
            'file' => $this->file,
            'line' => $this->line,
            'route' => $this->route,
            'middleware' => $this->middleware,
            'identifier' => $this->identifier,
            'lookup' => $this->lookup,
            'operation' => $this->operation,
            'principal' => $this->principal,
            'ownership_evidence' => $this->ownershipEvidence,
            'authorization_evidence' => $this->authorizationEvidence,
            'confidence' => $this->confidence,
            'trace' => $this->trace,
        ];
    }
}
