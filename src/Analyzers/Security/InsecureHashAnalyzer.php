<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Analyzers\Security;

use PhpParser\Node;
use Rampart\QualityChecker\Analysis\CountingNodeFinder;
use Rampart\QualityChecker\Result\Issue;
use Rampart\QualityChecker\Result\Severity;
use Rampart\QualityChecker\Profiling\Profiler;
use Rampart\QualityChecker\Scanning\ScanContextAware;
use Rampart\QualityChecker\Scanning\ScanContextTrait;

final class InsecureHashAnalyzer implements ScanContextAware
{
    use ScanContextTrait;

    private const RULE = 'INSECURE_HASH';

    private const WEAK_FUNCTIONS = ['md5', 'sha1'];

    private const WEAK_HASH_ALGOS = ['md5', 'sha1', 'md4'];

    /**
     * Not broken hashes but broken randomness: rand()/mt_rand() (Mersenne
     * Twister, seed-recoverable) and uniqid() (microtime-derived) are
     * predictable. Only flagged in token/secret context — counters,
     * shuffles and filenames stay silent.
     */
    private const WEAK_RANDOM_FUNCS = ['rand', 'mt_rand', 'uniqid'];

    private const TOKEN_NAME_PATTERN = '/token|otp|one[_-]?time|secret|passwd|password|api[_-]?key|private[_-]?key|verify|verification|reset|nonce|salt|auth[_-]?code|session[_-]?id/i';

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
        $code = $this->sharedSource($file);
        if ($code === '') {
            return [];
        }

        if (stripos($code, 'pwnedpasswords') !== false) {
            return [];
        }

        $ast = $this->sharedAst($file);
        if ($ast === null) {
            return [];
        }

        $issues = [];
        $finder = new CountingNodeFinder();

        $calls = $finder->find($ast, function (Node $node): bool {
            if (!$node instanceof Node\Expr\FuncCall || !$node->name instanceof Node\Name) {
                return false;
            }
            $name = strtolower($node->name->toString());

            return in_array($name, self::WEAK_FUNCTIONS, true)
                || in_array($name, self::WEAK_RANDOM_FUNCS, true)
                || $name === 'hash';
        });

        foreach ($calls as $call) {
            if (!$call instanceof Node\Expr\FuncCall) {
                continue;
            }
            if ($this->isWeakRandomCall($call)) {
                if (!$this->isTokenContext($call)) {
                    continue;
                }
                $fnName = $call->name instanceof Node\Name ? $call->name->toString() : 'rand';
                $issues[] = new Issue(
                    self::RULE,
                    sprintf('%s() is not cryptographically secure and must not generate tokens/OTPs/secrets; use random_int()/random_bytes().', $fnName),
                    $file,
                    $call->getStartLine(),
                    Severity::Warning,
                    'custom',
                    ['function' => $fnName]
                );
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
    private function isWeakRandomCall(Node\Expr\FuncCall $call): bool
    {
        if (!$call->name instanceof Node\Name) {
            return false;
        }

        return in_array(strtolower($call->name->toString()), self::WEAK_RANDOM_FUNCS, true);
    }

    /**
     * Token context: assigned to a token/secret-named variable, stored under
     * a token/secret-named array key (e.g. ['code' => mt_rand(...)]), or
     * returned from a token/secret-named function. Everything else (loop
     * counters, offsets, filenames) stays silent.
     */
    private function isTokenContext(Node\Expr\FuncCall $call): bool
    {
        $parent = $call->getAttribute('parent');
        // Unwrap a single cast: $otp = (string) mt_rand(...).
        if ($parent instanceof Node\Expr\Cast && $parent->getAttribute('parent') instanceof Node) {
            $parent = $parent->getAttribute('parent');
        }
        if ($parent instanceof Node\Expr\Assign && $parent->var instanceof Node\Expr\Variable && is_string($parent->var->name)) {
            return preg_match(self::TOKEN_NAME_PATTERN, $parent->var->name) === 1;
        }

        if (
            $parent instanceof Node\Expr\ArrayItem
            && $parent->key instanceof Node\Scalar\String_
            && preg_match(self::TOKEN_NAME_PATTERN, $parent->key->value) === 1
        ) {
            return true;
        }

        if ($parent instanceof Node\Stmt\Return_) {
            $owner = $parent->getAttribute('parent');
            while ($owner !== null && !$owner instanceof Node\Stmt\Function_ && !$owner instanceof Node\Stmt\ClassMethod) {
                $owner = $owner instanceof Node ? $owner->getAttribute('parent') : null;
            }
            if (
                ($owner instanceof Node\Stmt\Function_ || $owner instanceof Node\Stmt\ClassMethod)
                && $owner->name instanceof Node\Identifier
                && preg_match(self::TOKEN_NAME_PATTERN, $owner->name->toString()) === 1
            ) {
                return true;
            }
        }

        return false;
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

    /**
     * @param list<Node> $ast
     */
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
}
