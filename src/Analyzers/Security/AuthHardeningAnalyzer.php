<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Analyzers\Security;

use PhpParser\Node;
use Rampart\QualityChecker\Analysis\CountingNodeFinder;
use Rampart\QualityChecker\Result\Confidence;
use Rampart\QualityChecker\Result\Issue;
use Rampart\QualityChecker\Result\Severity;
use Rampart\QualityChecker\Profiling\Profiler;
use Rampart\QualityChecker\Scanning\ScanContextAware;
use Rampart\QualityChecker\Scanning\ScanContextTrait;

final class AuthHardeningAnalyzer implements ScanContextAware
{
    use ScanContextTrait;

    private const RULE_SESSION_FIXATION = 'SESSION_FIXATION';

    private const RULE_WEAK_PASSWORD_POLICY = 'WEAK_PASSWORD_POLICY';

    private const MIN_PASSWORD_LENGTH = 8;

    /**
     * Login-ish call names (case-insensitive). `$request->authenticate()` is
     * a different name on purpose and is not included.
     *
     * @var list<string>
     */
    private const LOGIN_METHODS = ['attempt', 'login', 'loginusingid'];

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

        $ast = $this->sharedAst($file);
        if ($ast === null) {
            return [];
        }

        $issues = [];
        foreach ($this->findSessionFixationIssues($file, $ast) as $issue) {
            $issues[] = $issue;
        }
        foreach ($this->findWeakPasswordPolicyIssues($file, $ast) as $issue) {
            $issues[] = $issue;
        }

        return $issues;
    }

    /**
     * A login-ish call with no session regeneration in the same function
     * scope is a session-fixation risk. Each function (and top-level code)
     * is its own scope: regeneration elsewhere does not count.
     *
     * @param list<Node> $ast
     * @return list<Issue>
     */
    private function findSessionFixationIssues(string $file, array $ast): array
    {
        $finder = new CountingNodeFinder();
        $calls = $finder->find($ast, static function (Node $node): bool {
            return $node instanceof Node\Expr\FuncCall
                || $node instanceof Node\Expr\MethodCall
                || $node instanceof Node\Expr\StaticCall;
        });

        /** @var array<string, array{function: string, logins: list<Node\Expr>, hasRegen: bool}> $scopes */
        $scopes = [];

        foreach ($calls as $call) {
            if (
                !$call instanceof Node\Expr\FuncCall
                && !$call instanceof Node\Expr\MethodCall
                && !$call instanceof Node\Expr\StaticCall
            ) {
                continue;
            }
            $name = $this->callName($call);
            if ($name === null) {
                continue;
            }
            $lower = strtolower($name);
            $isLogin = in_array($lower, self::LOGIN_METHODS, true);
            $isRegeneration = str_contains($lower, 'regenerate');
            if (!$isLogin && !$isRegeneration) {
                continue;
            }

            $owner = $this->enclosingFunction($call);
            if ($owner === null) {
                $key = '{top-level}';
                $functionName = '{top-level}';
            } else {
                $key = spl_object_hash($owner);
                $functionName = $owner->name instanceof Node\Identifier
                    ? $owner->name->toString()
                    : '{top-level}';
            }

            if (!isset($scopes[$key])) {
                $scopes[$key] = ['function' => $functionName, 'logins' => [], 'hasRegen' => false];
            }
            if ($isLogin) {
                $scopes[$key]['logins'][] = $call;
            }
            if ($isRegeneration) {
                $scopes[$key]['hasRegen'] = true;
            }
        }

        $issues = [];
        foreach ($scopes as $scope) {
            if ($scope['logins'] === [] || $scope['hasRegen']) {
                continue;
            }
            foreach ($scope['logins'] as $login) {
                $issues[] = new Issue(
                    self::RULE_SESSION_FIXATION,
                    sprintf(
                        'Login in function \'%s\' does not regenerate the session; call '
                        . '$request->session()->regenerate() after authentication to prevent session fixation.',
                        $scope['function']
                    ),
                    $file,
                    $login->getStartLine(),
                    Severity::Warning,
                    'custom',
                    ['function' => $scope['function']],
                    Confidence::Medium
                );
            }
        }

        return $issues;
    }

    /**
     * Weak password policies: Password::min(N) with a literal N below the
     * floor, and validation rule arrays for password-like keys with a short
     * (or missing) min: length rule.
     *
     * @param list<Node> $ast
     * @return list<Issue>
     */
    private function findWeakPasswordPolicyIssues(string $file, array $ast): array
    {
        $finder = new CountingNodeFinder();
        $issues = [];

        $staticCalls = $finder->findInstanceOf($ast, Node\Expr\StaticCall::class);
        foreach ($staticCalls as $call) {
            if (!$call instanceof Node\Expr\StaticCall) {
                continue;
            }
            $length = $this->weakPasswordMinLength($call);
            if ($length === null) {
                continue;
            }
            $issues[] = new Issue(
                self::RULE_WEAK_PASSWORD_POLICY,
                sprintf(
                    'Weak password policy: Password::min(%d) is below the %d-character minimum; '
                    . 'use Password::min(%d) or higher.',
                    $length,
                    self::MIN_PASSWORD_LENGTH,
                    self::MIN_PASSWORD_LENGTH
                ),
                $file,
                $call->getStartLine(),
                Severity::Warning,
                'custom',
                ['function' => 'min'],
                Confidence::Medium
            );
        }

        $arrays = $finder->findInstanceOf($ast, Node\Expr\Array_::class);
        foreach ($arrays as $array) {
            if (!$array instanceof Node\Expr\Array_) {
                continue;
            }
            if (!$this->isValidationRulesArray($array)) {
                continue;
            }
            foreach ($array->items as $item) {
                if (!$item instanceof Node\Expr\ArrayItem) {
                    continue;
                }
                if (!$item->key instanceof Node\Scalar\String_) {
                    continue;
                }
                if (preg_match('/passw/i', $item->key->value) !== 1) {
                    continue;
                }
                $finding = $this->weakPasswordRuleValue($item->value);
                if ($finding === null) {
                    continue;
                }
                $issues[] = new Issue(
                    self::RULE_WEAK_PASSWORD_POLICY,
                    sprintf(
                        'Weak password policy for \'%s\': %s Require at least %d characters (e.g. \'min:%d\').',
                        $item->key->value,
                        $finding,
                        self::MIN_PASSWORD_LENGTH,
                        self::MIN_PASSWORD_LENGTH
                    ),
                    $file,
                    $item->getStartLine(),
                    Severity::Warning,
                    'custom',
                    ['field' => $item->key->value],
                    Confidence::Medium
                );
            }
        }

        return $issues;
    }

    /**
     * Length N of a Password::min(N) call when N is a literal int below the
     * floor, null otherwise. Only the Password rule builder counts; any
     * other class with a min() method is out of scope.
     */
    private function weakPasswordMinLength(Node\Expr\StaticCall $call): ?int
    {
        if (!$call->name instanceof Node\Identifier) {
            return null;
        }
        if (strtolower($call->name->toString()) !== 'min') {
            return null;
        }
        if (!$call->class instanceof Node\Name) {
            return null;
        }
        $parts = explode('\\', strtolower(ltrim($call->class->toString(), '\\')));
        if (end($parts) !== 'password') {
            return null;
        }
        $arg = $call->args[0] ?? null;
        if (!$arg instanceof Node\Arg || !$arg->value instanceof Node\Scalar\Int_) {
            return null;
        }
        if ($arg->value->value >= self::MIN_PASSWORD_LENGTH) {
            return null;
        }

        return $arg->value->value;
    }

    /**
     * Only arrays that look like validation rules count: arrays returned
     * from a rules() method, or the RULES argument of validate() /
     * Validator::make() / validateWithBag() — not the custom-messages
     * argument (whose 'password.min' keys name messages, not fields).
     */
    private function isValidationRulesArray(Node\Expr\Array_ $array): bool
    {
        $node = $array;
        while (true) {
            $parent = $node->getAttribute('parent');
            if (!$parent instanceof Node) {
                return false;
            }
            if ($parent instanceof Node\Stmt\ClassMethod) {
                return strtolower($parent->name->toString()) === 'rules';
            }
            if ($parent instanceof Node\Stmt\Function_) {
                return strtolower($parent->name->toString()) === 'rules';
            }
            if ($parent instanceof Node\Arg) {
                return $this->isRulesArgument($parent);
            }
            if (
                $parent instanceof Node\Expr\Array_
                || $parent instanceof Node\Expr\ArrayItem
                || $parent instanceof Node\Expr\Assign
                || $parent instanceof Node\Stmt\Return_
                || $parent instanceof Node\Stmt\Expression
            ) {
                $node = $parent;
                continue;
            }

            return false;
        }
    }

    /**
     * The argument holding validation RULES (not custom messages):
     * validate($rules, ...), validateWithBag($bag, $rules, ...),
     * Validator::make($data, $rules, ...), or a named rules: argument.
     */
    private function isRulesArgument(Node\Arg $arg): bool
    {
        $call = $arg->getAttribute('parent');
        if (
            !$call instanceof Node\Expr\FuncCall
            && !$call instanceof Node\Expr\MethodCall
            && !$call instanceof Node\Expr\StaticCall
        ) {
            return false;
        }
        if ($arg->name instanceof Node\Identifier) {
            return strtolower($arg->name->toString()) === 'rules';
        }
        $index = null;
        foreach ($call->args as $i => $candidate) {
            if ($candidate === $arg) {
                $index = $i;
                break;
            }
        }
        if ($index === null) {
            return false;
        }
        $name = $this->callName($call);
        if ($name === null) {
            return false;
        }
        $lower = strtolower($name);
        if ($lower === 'validate') {
            return $index === 0;
        }
        if ($lower === 'validatewithbag') {
            return $index === 1;
        }
        if ($lower === 'make') {
            return $index === 1
                && $call instanceof Node\Expr\StaticCall
                && $call->class instanceof Node\Name
                && str_contains(strtolower($call->class->toString()), 'validator');
        }

        return false;
    }

    /**
     * Describe why a password rule value is weak, or null when it is fine.
     * String rules are split on '|' and each segment is checked for
     * ^min:(\d+); arrays of string rules must contain a min: rule meeting
     * the floor. Non-string rule values (rule objects such as
     * Password::min(8)) are out of scope here.
     */
    private function weakPasswordRuleValue(?Node\Expr $value): ?string
    {
        if ($value instanceof Node\Scalar\String_) {
            $hasMin = false;
            foreach (explode('|', $value->value) as $segment) {
                $segment = trim($segment);
                if (preg_match('/^min:(\d+)/', $segment, $matches) !== 1) {
                    continue;
                }
                $hasMin = true;
                if ((int) $matches[1] < self::MIN_PASSWORD_LENGTH) {
                    return sprintf('minimum length %d is below the minimum; ', (int) $matches[1]);
                }
            }
            if (!$hasMin) {
                return 'no minimum length rule is defined; ';
            }

            return null;
        }

        if ($value instanceof Node\Expr\Array_) {
            $segments = [];
            foreach ($value->items as $item) {
                if (!$item instanceof Node\Expr\ArrayItem || $item->unpack) {
                    return null;
                }
                if (!$item->value instanceof Node\Scalar\String_) {
                    return null;
                }
                foreach (explode('|', $item->value->value) as $segment) {
                    $segments[] = trim($segment);
                }
            }
            $hasMin = false;
            foreach ($segments as $segment) {
                if (preg_match('/^min:(\d+)/', $segment, $matches) !== 1) {
                    continue;
                }
                $hasMin = true;
                if ((int) $matches[1] < self::MIN_PASSWORD_LENGTH) {
                    return sprintf('minimum length %d is below the minimum; ', (int) $matches[1]);
                }
            }
            if (!$hasMin) {
                return 'no minimum length rule is defined; ';
            }

            return null;
        }

        return null;
    }

    /**
     * Nearest enclosing ClassMethod or Function_; closures do not open a
     * new scope, so calls inside a closure belong to the outer function.
     */
    private function enclosingFunction(Node $node): Node\Stmt\ClassMethod|Node\Stmt\Function_|null
    {
        $parent = $node->getAttribute('parent');
        while ($parent instanceof Node) {
            if ($parent instanceof Node\Stmt\ClassMethod || $parent instanceof Node\Stmt\Function_) {
                return $parent;
            }
            $parent = $parent->getAttribute('parent');
        }

        return null;
    }

    private function callName(Node\Expr $call): ?string
    {
        if ($call instanceof Node\Expr\FuncCall) {
            return $call->name instanceof Node\Name ? $call->name->toString() : null;
        }
        if ($call instanceof Node\Expr\MethodCall) {
            return $call->name instanceof Node\Identifier ? $call->name->toString() : null;
        }
        if ($call instanceof Node\Expr\StaticCall) {
            return $call->name instanceof Node\Identifier ? $call->name->toString() : null;
        }

        return null;
    }

    private function isTestPath(string $path): bool
    {
        $normalized = strtolower(str_replace('\\', '/', $path));

        return str_contains($normalized, '/tests/');
    }
}
