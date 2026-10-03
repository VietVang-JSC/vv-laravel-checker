<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Semantic;

use Rampart\QualityChecker\Result\Confidence;
use Rampart\QualityChecker\Result\Issue;
use Rampart\QualityChecker\Result\Severity;

/**
 * Maps a shadow ownership decision onto a production finding.
 *
 * v0.6.2 production mapping (conservative, asymmetric):
 * - PROTECTED -> null (positive proof suppresses the ownership concern;
 *   it never suppresses BAC's own findings — that is the checker's job
 *   to NOT do).
 * - UNKNOWN -> null (an engine limitation is not a developer finding).
 * - REVIEW -> an Issue only on a strong chain (request identifier plus a
 *   concrete model lookup). Weak chains stay shadow-only unless the checker
 *   enriches an existing BAC finding with them.
 * - EXPOSED -> always an Issue (public plus sensitive write); confidence
 *   tracks chain strength.
 *
 * Messages say "could not be proven", never "IDOR vulnerability".
 *
 * This is the whole production-mapping policy in one place. It used to live
 * inside OwaspOwnershipAnalyzer (a 1200-line AST analyzer) even though it
 * touches no AST at all — the checker drives it when reconciling shadow
 * decisions against existing BAC findings, so the analyzer was never the only
 * consumer.
 */
final class OwnershipIssueMapper
{
    /**
     * @return Issue|null null when the decision must not surface on its own
     */
    public function toProductionIssue(OwnershipDecision $decision, string $rule): ?Issue
    {
        if (
            $decision->status === OwnershipDecision::PROTECTED
            || $decision->status === OwnershipDecision::UNKNOWN
        ) {
            return null;
        }

        $strong = $this->isStrongChain($decision);
        if ($decision->status === OwnershipDecision::REVIEW && !$strong) {
            return null;
        }

        $resource = $decision->lookup['detail'] ?? $decision->identifier['detail'] ?? $decision->method . '()';
        $identifier = $decision->identifier['detail'] ?? 'request input';
        $operation = $decision->operation['detail'] ?? 'write';

        if ($decision->status === OwnershipDecision::EXPOSED) {
            return $this->issue(
                $rule,
                sprintf(
                    'Publicly reachable %s() performs %s on %s identified by %s without proven ownership or access control.',
                    $decision->method,
                    $operation,
                    $resource,
                    $identifier
                ),
                $decision,
                $strong ? Confidence::High : Confidence::Medium
            );
        }

        return $this->issue(
            $rule,
            sprintf(
                'Object-level authorization could not be proven: %s() performs %s on %s identified by %s — ownership unverified.',
                $decision->method,
                $operation,
                $resource,
                $identifier
            ),
            $decision,
            Confidence::Medium
        );
    }

    /**
     * A chain strong enough to surface on its own: a request identifier
     * reaching a concrete (non-dynamic) model lookup.
     */
    public function isStrongChain(OwnershipDecision $decision): bool
    {
        return $decision->identifier !== null
            && $decision->lookup !== null
            && $decision->lookup['kind'] !== 'dynamic';
    }

    private function issue(
        string $rule,
        string $message,
        OwnershipDecision $decision,
        Confidence $confidence
    ): Issue {
        return new Issue(
            $rule,
            $message,
            $decision->file,
            $decision->line,
            Severity::Error,
            'custom',
            $this->provenanceMetadata($decision),
            $confidence
        );
    }

    /**
     * Full evidence chain travels into production (v0.6.2 provenance):
     * flat controller/action keys for checker dedup identity plus the
     * nested ownership block.
     *
     * @return array<string, mixed>
     */
    public function provenanceMetadata(OwnershipDecision $decision): array
    {
        return [
            'controller' => $decision->controller,
            'action' => $decision->method,
            'method' => $decision->method,
            'access_control' => [
                'decision' => $decision->status,
                'ownership' => $decision->toArray(),
            ],
        ];
    }
}
