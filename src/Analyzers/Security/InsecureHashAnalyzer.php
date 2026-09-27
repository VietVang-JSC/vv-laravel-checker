<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Analyzers\Security;

use PhpParser\Node;
use PhpParser\NodeFinder;
use PhpParser\ParserFactory;
use VietVang\QualityChecker\Result\Issue;
use VietVang\QualityChecker\Result\Severity;

final class InsecureHashAnalyzer
{
    private const RULE = 'INSECURE_HASH';

    private const WEAK_FUNCTIONS = ['md5', 'sha1'];

    private const WEAK_HASH_ALGOS = ['md5', 'sha1', 'md4'];

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
        $code = $this->readFile($file);
        if ($code === '') {
            return [];
        }

        if (stripos($code, 'pwnedpasswords') !== false) {
            return [];
        }

        $ast = $this->parse($code);
        if ($ast === null) {
            return [];
        }

        $issues = [];
        $finder = new NodeFinder();

        $calls = $finder->find($ast, function (Node $node): bool {
            if (!$node instanceof Node\Expr\FuncCall || !$node->name instanceof Node\Name) {
                return false;
            }
            $name = strtolower($node->name->toString());

            return in_array($name, self::WEAK_FUNCTIONS, true) || $name === 'hash';
        });

        foreach ($calls as $call) {
            if (!$call instanceof Node\Expr\FuncCall) {
                continue;
            }
            if (!$this->isWeakHashCall($call)) {
                continue;
            }
            if (!$this->isCredentialContext($call, $ast)) {
                continue;
            }

            $fnName = $call->name instanceof Node\Name ? $call->name->toString() : 'hash';
            $issues[] = new Issue(
                self::RULE,
                sprintf('%s() is used in a password/credential context; use a secure password hash (password_hash/bcrypt/argon2).', $fnName),
                $file,
                $call->getStartLine(),
                Severity::Warning,
                'custom',
                ['function' => $fnName]
            );
        }

        return $issues;
    }

    /**
     * md5()/sha1() always count; hash() only counts with a weak first
     * algorithm argument (md5/sha1/md4 literal).
     */
    private function isWeakHashCall(Node\Expr\FuncCall $call): bool
    {
        if (!$call->name instanceof Node\Name) {
            return false;
        }
        $name = strtolower($call->name->toString());
        if (in_array($name, self::WEAK_FUNCTIONS, true)) {
            return true;
        }
        if ($name !== 'hash') {
            return false;
        }
        $algo = $call->args[0] ?? null;
        if (!$algo instanceof Node\Arg || !$algo->value instanceof Node\Scalar\String_) {
            return false;
        }

        return in_array(strtolower($algo->value->value), self::WEAK_HASH_ALGOS, true);
    }

    private function isCredentialContext(Node\Expr\FuncCall $call, array $ast): bool
    {
        $args = $call->args;

        foreach ($args as $arg) {
            $value = $arg instanceof Node\Arg ? $arg->value : $arg;
            if ($this->refersToPassword($value)) {
                return true;
            }
        }

        $parent = $call->getAttribute('parent');
        if (
            $parent instanceof Node\Expr\BinaryOp
            && in_array($parent->getType(), ['Expr_BinaryOp_Identical', 'Expr_BinaryOp_NotIdentical', 'Expr_BinaryOp_Equal', 'Expr_BinaryOp_NotEqual'], true)
        ) {
            $other = $parent->left === $call ? $parent->right : $parent->left;
            if ($this->refersToPassword($other)) {
                return true;
            }
        }

        $sourceCode = $this->readSourceAround($call);
        if (preg_match('/password/i', $sourceCode) === 1) {
            return true;
        }

        return false;
    }

    private function refersToPassword(Node\Expr $expr): bool
    {
        if ($expr instanceof Node\Expr\Variable && is_string($expr->name)) {
            return stripos($expr->name, 'password') !== false || stripos($expr->name, 'passwd') !== false;
        }

        if ($expr instanceof Node\Expr\PropertyFetch && $expr->name instanceof Node\Identifier) {
            return stripos($expr->name->toString(), 'password') !== false;
        }

        if ($expr instanceof Node\Scalar\String_) {
            return preg_match('/password|passwd/i', $expr->value) === 1;
        }

        return false;
    }

    private function readSourceAround(Node\Expr\FuncCall $call): string
    {
        $attrs = $call->getAttributes();

        return (string) ($attrs['comments'][0] ?? '');
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
            $ast = $parser->parse($code);
            if ($ast === null) {
                return null;
            }

            $traverser = new \PhpParser\NodeTraverser();
            $traverser->addVisitor(new \PhpParser\NodeVisitor\ParentConnectingVisitor());
            $traverser->traverse($ast);

            return $ast;
        } catch (\Throwable $e) {
            return null;
        }
    }
}
