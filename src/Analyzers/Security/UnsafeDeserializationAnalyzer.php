<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Analyzers\Security;

use PhpParser\Node;
use PhpParser\NodeFinder;
use PhpParser\ParserFactory;
use VietVang\QualityChecker\Result\Issue;
use VietVang\QualityChecker\Result\Severity;

final class UnsafeDeserializationAnalyzer
{
    private const RULE = 'UNSAFE_UNSERIALIZE';

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

        $calls = $finder->findInstanceOf($ast, Node\Expr\FuncCall::class);
        foreach ($calls as $call) {
            if (!$call->name instanceof Node\Name) {
                continue;
            }
            $functionName = $call->name->toString();

            if ($functionName === 'unserialize') {
                $arg = $call->args[0] ?? null;
                if ($arg === null) {
                    continue;
                }
                if ($this->isLiteralOrConstant($arg->value)) {
                    continue;
                }
                $issues[] = new Issue(
                    self::RULE,
                    'unserialize() is called with a non-literal (potentially untrusted) argument.',
                    $file,
                    $call->getStartLine(),
                    Severity::Critical,
                    'custom',
                    ['function' => 'unserialize']
                );
            }

            if ($functionName === 'ini_set' || $functionName === 'set_error_handler') {
                $arg = $call->args[0] ?? null;
                $arg2 = $call->args[1] ?? null;
                $argName = $arg instanceof Node\Arg ? $this->argLiteralString($arg->value) : null;
                if ($argName === 'unserialize_callback_func') {
                    if ($arg2 === null || $this->isLiteralOrConstant($arg2->value)) {
                        continue;
                    }
                    $issues[] = new Issue(
                        self::RULE,
                        'unserialize_callback_func is set to a non-literal callback, allowing arbitrary code execution on unserialize.',
                        $file,
                        $call->getStartLine(),
                        Severity::Critical,
                        'custom',
                        ['function' => 'unserialize_callback_func']
                    );
                }
            }
        }

        return $issues;
    }

    private function isLiteralOrConstant(Node\Expr $expr): bool
    {
        return $expr instanceof Node\Scalar
            || $expr instanceof Node\Expr\ClassConstFetch
            || $expr instanceof Node\Expr\ConstFetch;
    }

    private function argLiteralString(Node\Expr $expr): ?string
    {
        if ($expr instanceof Node\Scalar\String_) {
            return $expr->value;
        }

        return null;
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
