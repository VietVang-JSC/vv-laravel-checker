<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Analyzers\Security;

use PhpParser\Node;
use PhpParser\NodeFinder;
use PhpParser\ParserFactory;
use VietVang\QualityChecker\Result\Issue;
use VietVang\QualityChecker\Result\Severity;

final class InsecureCookieAnalyzer
{
    private const RULE = 'INSECURE_COOKIE';

    private const SECURE_INDEX = 5;

    private const STATIC_METHODS = ['queue', 'make', 'forever'];

    private const RECEIVER_SUFFIXES = ['cookie', 'cookiejar', 'response', 'redirectresponse', 'jsonresponse'];

    /**
     * @param list<string> $files
     * @return list<Issue>
     */
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

    /**
     * @return list<Issue>
     */
    public function analyzeFile(string $file): array
    {
        if ($this->isTestPath($file)) {
            return [];
        }
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
        $calls = $finder->find($ast, static function (Node $node): bool {
            if ($node instanceof Node\Expr\FuncCall) {
                return $node->name instanceof Node\Name && $node->name->toString() === 'cookie';
            }
            if ($node instanceof Node\Expr\StaticCall) {
                return $node->name instanceof Node\Identifier
                    && in_array(strtolower($node->name->toString()), self::STATIC_METHODS, true);
            }
            if ($node instanceof Node\Expr\MethodCall) {
                return $node->name instanceof Node\Identifier
                    && strtolower($node->name->toString()) === 'cookie';
            }

            return false;
        });

        foreach ($calls as $call) {
            if ($call instanceof Node\Expr\FuncCall) {
                $label = 'cookie';
            } elseif ($call instanceof Node\Expr\StaticCall) {
                $label = $this->staticCallLabel($call);
                if ($label === null) {
                    continue;
                }
            } elseif ($call instanceof Node\Expr\MethodCall) {
                if (!$this->isResponseReceiver($call->var)) {
                    continue;
                }
                $label = 'cookie';
            } else {
                continue;
            }

            $finding = $this->secureFinding($call->args);
            if ($finding === null) {
                continue;
            }
            if ($finding === 'false') {
                $issues[] = new Issue(
                    self::RULE,
                    sprintf('%s() sets a cookie with $secure = false, so the cookie is sent over plain HTTP.', $label),
                    $file,
                    $call->getStartLine(),
                    Severity::Error,
                    'custom',
                    ['function' => $label]
                );
                continue;
            }
            $issues[] = new Issue(
                self::RULE,
                sprintf('%s() sets a cookie without an explicit $secure flag and relies on session config - verify session.secure_cookie.', $label),
                $file,
                $call->getStartLine(),
                Severity::Warning,
                'custom',
                ['function' => $label]
            );
        }

        return $issues;
    }

    private function staticCallLabel(Node\Expr\StaticCall $call): ?string
    {
        if (!$call->class instanceof Node\Name || !$call->name instanceof Node\Identifier) {
            return null;
        }
        $class = $call->class->toString();
        if (!$this->matchesSuffix($class)) {
            return null;
        }
        $pos = strrpos($class, '\\');
        $short = $pos === false ? $class : substr($class, $pos + 1);

        return $short . '::' . $call->name->toString();
    }

    private function isResponseReceiver(Node\Expr $receiver): bool
    {
        $name = $this->receiverName($receiver);
        if ($name === null) {
            return true;
        }
        if (strtolower($name) === 'redirect') {
            return true;
        }

        return $this->matchesSuffix($name);
    }

    private function receiverName(Node\Expr $receiver): ?string
    {
        if ($receiver instanceof Node\Expr\Variable && is_string($receiver->name)) {
            return $receiver->name;
        }
        if ($receiver instanceof Node\Expr\FuncCall && $receiver->name instanceof Node\Name) {
            return $receiver->name->toString();
        }
        if (
            ($receiver instanceof Node\Expr\MethodCall || $receiver instanceof Node\Expr\NullsafeMethodCall)
            && $receiver->name instanceof Node\Identifier
        ) {
            return $receiver->name->toString();
        }
        if ($receiver instanceof Node\Expr\StaticCall && $receiver->name instanceof Node\Identifier) {
            return $receiver->name->toString();
        }
        if ($receiver instanceof Node\Expr\New_ && $receiver->class instanceof Node\Name) {
            return $receiver->class->toString();
        }

        return null;
    }

    private function matchesSuffix(string $name): bool
    {
        $lower = strtolower($name);
        foreach (self::RECEIVER_SUFFIXES as $suffix) {
            if (str_ends_with($lower, $suffix)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param list<Node\Arg|Node\VariadicPlaceholder> $args
     * @return 'missing'|'false'|null
     */
    private function secureFinding(array $args): ?string
    {
        foreach ($args as $arg) {
            if (
                $arg instanceof Node\Arg
                && $arg->name instanceof Node\Identifier
                && $arg->name->toString() === 'secure'
            ) {
                return $this->isFalseLiteral($arg->value) ? 'false' : null;
            }
        }

        $positional = [];
        foreach ($args as $arg) {
            if ($arg instanceof Node\Arg && $arg->name === null) {
                $positional[] = $arg;
            }
        }
        $secure = $positional[self::SECURE_INDEX] ?? null;
        if (!$secure instanceof Node\Arg) {
            return 'missing';
        }
        if ($this->isFalseLiteral($secure->value)) {
            return 'false';
        }

        return null;
    }

    private function isFalseLiteral(Node\Expr $expr): bool
    {
        return $expr instanceof Node\Expr\ConstFetch
            && strtolower($expr->name->toString()) === 'false';
    }

    private function isTestPath(string $path): bool
    {
        $normalized = strtolower(str_replace('\\', '/', $path));

        return str_contains($normalized, '/tests/')
            || str_contains($normalized, '/test/')
            || str_ends_with($normalized, 'test.php');
    }

    private function readFile(string $path): string
    {
        if (!is_file($path)) {
            return '';
        }

        return (string) file_get_contents($path);
    }

    /**
     * @return list<Node>|null
     */
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
