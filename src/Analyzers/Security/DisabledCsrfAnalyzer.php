<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Analyzers\Security;

use PhpParser\Node;
use PhpParser\NodeFinder;
use PhpParser\ParserFactory;
use VietVang\QualityChecker\Result\Issue;
use VietVang\QualityChecker\Result\Severity;

final class DisabledCsrfAnalyzer
{
    private const RULE_AUTHORIZE_TRUE = 'DISABLED_CSRF_AUTHORIZE_TRUE';
    private const RULE_EXCEPTION_STAR = 'DISABLED_CSRF_EXCEPTION_STAR';

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

    public function supports(string $path): bool
    {
        return strtolower((string) pathinfo($path, PATHINFO_EXTENSION)) === 'php';
    }

    public function analyzeFile(string $file): array
    {
        $code = $this->readFile($file);
        if ($code === '') {
            return [];
        }

        $ast = $this->parse($code);
        if ($ast === null) {
            return [];
        }

        $issues = [];
        $finder = new NodeFinder();

        foreach ($finder->findInstanceOf($ast, Node\Stmt\Class_::class) as $class) {
            if ($this->isFormRequest($class)) {
                $authorize = $this->findMethod($class, 'authorize');
                if ($authorize !== null && $this->returnsLiteralTrue($authorize)) {
                    $issues[] = new Issue(
                        self::RULE_AUTHORIZE_TRUE,
                        'FormRequest::authorize() always returns literal true, disabling authorization for this request.',
                        $file,
                        $authorize->getStartLine(),
                        Severity::Warning,
                        'custom',
                        ['class' => $this->className($class)]
                    );
                }
            }

            if ($this->isVerifyCsrfToken($class)) {
                $except = $this->findProperty($class, 'except');
                $patterns = $except !== null ? $this->wildcardPatterns($except) : [];
                if ($patterns !== []) {
                    $apiOnly = $patterns !== [] && $this->isApiOnlyExclusion($patterns);
                    $issues[] = new Issue(
                        self::RULE_EXCEPTION_STAR,
                        $apiOnly
                            ? 'VerifyCsrfToken::$except excludes "api/*": acceptable only for stateless (token-authenticated) APIs — verify no session-authenticated route lives under /api/.'
                            : 'VerifyCsrfToken::$except contains a broad wildcard pattern ("*"), disabling CSRF protection.',
                        $file,
                        $except->getStartLine(),
                        $apiOnly ? Severity::Warning : Severity::Critical,
                        'custom',
                        ['class' => $this->className($class)]
                    );
                }
            }
        }

        return $issues;
    }

    private function isFormRequest(Node\Stmt\Class_ $class): bool
    {
        if ($class->extends === null) {
            return false;
        }

        return $this->matches($class->extends, 'Illuminate\\Foundation\\Http\\FormRequest');
    }

    private function isVerifyCsrfToken(Node\Stmt\Class_ $class): bool
    {
        $name = $class->name ? $class->name->toString() : '';
        if ($name === 'VerifyCsrfToken') {
            return true;
        }
        if ($class->extends !== null && $this->matches($class->extends, 'VerifyCsrfToken')) {
            return true;
        }

        return false;
    }

    private function findMethod(Node\Stmt\Class_ $class, string $name): ?Node\Stmt\ClassMethod
    {
        foreach ($class->getMethods() as $method) {
            if ($method->name instanceof Node\Identifier && $method->name->toString() === $name) {
                return $method;
            }
        }

        return null;
    }

    private function findProperty(Node\Stmt\Class_ $class, string $name): ?Node\Stmt\Property
    {
        foreach ($class->getProperties() as $property) {
            foreach ($property->props as $prop) {
                if ($prop->name instanceof Node\Identifier && $prop->name->toString() === $name) {
                    return $property;
                }
            }
        }

        return null;
    }

    private function returnsLiteralTrue(Node\Stmt\ClassMethod $method): bool
    {
        $finder = new NodeFinder();
        $returns = $finder->findInstanceOf($method, Node\Stmt\Return_::class);

        foreach ($returns as $return) {
            if ($return->expr instanceof Node\Expr\ConstFetch) {
                $name = $return->expr->name instanceof Node\Name ? strtolower($return->expr->name->toString()) : '';
                if ($name === 'true') {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * @return list<string> wildcard patterns in $except
     */
    private function wildcardPatterns(Node\Stmt\Property $property): array
    {
        $items = $property->props[0]->default ?? null;
        if (!$items instanceof Node\Expr\Array_) {
            return [];
        }

        $patterns = [];
        foreach ($items->items as $item) {
            if ($item === null || $item->value === null) {
                continue;
            }
            $value = $item->value;
            if ($value instanceof Node\Scalar\String_ && str_contains($value->value, '*')) {
                $patterns[] = $value->value;
            }
        }

        return $patterns;
    }

    /**
     * @param list<string> $patterns
     */
    private function isApiOnlyExclusion(array $patterns): bool
    {
        foreach ($patterns as $pattern) {
            if ($pattern !== 'api/*') {
                return false;
            }
        }

        return true;
    }

    private function matches(Node\Name $name, string $target): bool
    {
        $resolved = $name->toString();
        if ($resolved === $target || str_ends_with($resolved, '\\' . $target)) {
            return true;
        }

        return false;
    }

    private function className(Node\Stmt\Class_ $class): string
    {
        return $class->name ? $class->name->toString() : '(anonymous)';
    }

    private function readFile(string $path): string
    {
        if (!is_file($path)) {
            return '';
        }

        return (string) file_get_contents($path);
    }

    private function parse(string $code): ?array
    {
        try {
            $parser = (new ParserFactory())->createForNewestSupportedVersion();

            return $parser->parse($code);
        } catch (\Throwable $e) {
            return null;
        }
    }
}
