<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Semantic;

/**
 * One resolved route: which controller action answers which HTTP
 * method(s) at which URI, under which middleware stack, and where it
 * was declared. This IS the evidence unit — never a bare boolean:
 * consumers can cite file/line and middleware instead of guessing.
 *
 * Unknown stays unknown: a dynamic URI or action resolves to null
 * rather than a guess.
 */
final class RouteNode
{
    /**
     * @param list<string> $methods lowercase HTTP verbs
     * @param list<string> $middleware middleware stack, outermost first
     */
    public function __construct(
        public readonly array $methods,
        public readonly ?string $uri,
        public readonly ?string $controller,
        public readonly ?string $action,
        public readonly array $middleware,
        public readonly string $file,
        public readonly ?int $line,
    ) {
    }
}
