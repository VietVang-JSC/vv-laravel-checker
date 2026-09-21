<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Analyzers\Owasp;

use PhpParser\Node;
use VietVang\QualityChecker\Analyzers\AbstractAnalyzer;
use VietVang\QualityChecker\Result\Issue;
use VietVang\QualityChecker\Result\Severity;

/**
 * A01 Broken Access Control.
 *
 * Assumes: only mutating controller methods (by name or persistence call) are flagged, and only
 * when no authorization/abort/middleware call appears in the method body or constructor/property.
 * Intentionally conservative to keep false positives low; does not resolve route/group config.
 */
final class OwaspAccessControlAnalyzer extends AbstractAnalyzer
{
    private const RULE = 'OWASP_BROKEN_ACCESS_CONTROL';

    private const MUTATING_METHODS = [
        'store', 'update', 'delete', 'destroy', 'restore', 'forceDelete',
    ];

    private const MUTATING_CALLS = ['save', 'delete', 'update', 'create', 'insert', 'upsert', 'destroy'];

    public function analyze(array $files): array
    {
        $issues = [];
        foreach ($files as $file) {
            if (!$this->supports($file)) {
                continue;
            }
            foreach ($this->analyzeFile($file) as $issue) {
                $issues[] = $issue;
            }
        }

        return $issues;
    }

    private function analyzeFile(string $file): array
    {
        $ast = $this->parse($this->readFile($file));
        if ($ast === null) {
            return [];
        }

        $issues = [];
        $classes = $this->finder()->findInstanceOf($ast, Node\Stmt\Class_::class);
        foreach ($classes as $class) {
            if (!$class instanceof Node\Stmt\Class_ || !$this->isControllerClass($class)) {
                continue;
            }
            foreach ($this->analyzeController($class, $file) as $issue) {
                $issues[] = $issue;
            }
        }

        return $issues;
    }

    private function isControllerClass(Node\Stmt\Class_ $class): bool
    {
        if ($class->name === null || $class->name->toString() === '') {
            return false;
        }

        // Skip abstract base classes and non-controllers.
        if ($class->isAbstract()) {
            return false;
        }

        return str_ends_with($class->name->toString(), 'Controller');
    }

    /**
     * @return Issue[]
     */
    private function analyzeController(Node\Stmt\Class_ $class, string $file): array
    {
        $issues = [];
        $hasAuthContext = $this->classHasAuthContext($class);

        foreach ($class->stmts as $stmt) {
            if (!$stmt instanceof Node\Stmt\ClassMethod) {
                continue;
            }
            if (!$stmt->isPublic() || $stmt->isMagic()) {
                continue;
            }

            $methodName = $stmt->name->toString();
            if (!$this->isMutatingMethod($stmt)) {
                continue;
            }
            if ($hasAuthContext || $this->methodHasAuth($stmt)) {
                continue;
            }

            $issues[] = $this->makeIssue(
                self::RULE,
                sprintf('Mutating method %s() has no visible authorization check.', $methodName),
                $file,
                $stmt->getStartLine(),
                Severity::Error,
                ['method' => $methodName]
            );
        }

        return $issues;
    }

    private function classHasAuthContext(Node\Stmt\Class_ $class): bool
    {
        foreach ($class->stmts as $stmt) {
            if ($stmt instanceof Node\Stmt\Property) {
                foreach ($stmt->props as $prop) {
                    if (in_array($prop->name->toString(), ['middleware', 'authorize'], true)) {
                        return true;
                    }
                }
            }

            if ($stmt instanceof Node\Stmt\ClassMethod && $stmt->name->toString() === '__construct') {
                if ($stmt->stmts !== null && $this->bodyHasAuth($stmt->stmts)) {
                    return true;
                }
            }
        }

        return false;
    }

    private function isMutatingMethod(Node\Stmt\ClassMethod $method): bool
    {
        $name = $method->name->toString();
        if (in_array($name, self::MUTATING_METHODS, true)) {
            return true;
        }

        if ($method->stmts === null) {
            return false;
        }

        $calls = $this->finder()->find($method->stmts, function (Node $node): bool {
            if (!$node instanceof Node\Expr\MethodCall) {
                return false;
            }

            return $node->name instanceof Node\Identifier
                && in_array($node->name->toString(), self::MUTATING_CALLS, true);
        });

        return $calls !== [];
    }

    private function methodHasAuth(Node\Stmt\ClassMethod $method): bool
    {
        if ($method->stmts === null) {
            return false;
        }

        return $this->bodyHasAuth($method->stmts);
    }

    /**
     * @param array<Node\Stmt> $stmts
     */
    private function bodyHasAuth(array $stmts): bool
    {
        foreach ($stmts as $stmt) {
            $found = $this->finder()->find($stmt, function (Node $node): bool {
                if (
                    $node instanceof Node\Expr\MethodCall
                    && $node->name instanceof Node\Identifier
                    && in_array($node->name->toString(), ['authorize', 'authorizeResource', 'middleware', 'abort', 'abortIf', 'abortUnless'], true)
                ) {
                    return true;
                }

                if (
                    $node instanceof Node\Expr\StaticCall
                    && $node->name instanceof Node\Identifier
                    && in_array($node->name->toString(), ['allow', 'deny', 'authorize', 'abort', 'abortIf', 'abortUnless'], true)
                    && $node->class instanceof Node\Name
                    && ($node->class->toString() === 'Gate' || str_ends_with($node->class->toString(), '\\Gate'))
                ) {
                    return true;
                }

                if (
                    $node instanceof Node\Expr\FuncCall
                    && $node->name instanceof Node\Name
                    && in_array($node->name->toString(), ['abort', 'abort_if', 'abort_unless'], true)
                ) {
                    return true;
                }

                return false;
            });

            if ($found !== []) {
                return true;
            }
        }

        return false;
    }
}
