<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Analyzers\Convention;

use PhpParser\Node;
use Rampart\QualityChecker\Analysis\CountingNodeFinder;
use Rampart\QualityChecker\Result\Confidence;
use Rampart\QualityChecker\Result\Issue;
use Rampart\QualityChecker\Result\Severity;
use Rampart\QualityChecker\Scanning\ScanContextAware;
use Rampart\QualityChecker\Scanning\ScanContextTrait;

final class DeadCodeAnalyzer implements ScanContextAware
{
    use ScanContextTrait;

    private const RULE = 'DEAD_CODE';

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

    private function analyzeFile(string $file): array
    {
        $code = $this->sharedSource($file);
        if ($code === '') {
            return [];
        }

        $ast = $this->sharedAst($file);
        if ($ast === null) {
            return [];
        }

        $issues = [];
        $finder = new CountingNodeFinder();

        foreach ($finder->findInstanceOf($ast, Node\Stmt\Class_::class) as $class) {
            foreach ($class->getMethods() as $method) {
                if (!$this->isCandidate($method)) {
                    continue;
                }

                // ClassMethod::$name is always an Identifier (php-parser 5),
                // so there is no null branch to guard.
                $methodName = $method->name->toString();

                if ($this->methodIsReferencedInFile($code, $methodName, $method->getStartLine())) {
                    continue;
                }

                $className = $class->name ? $class->name->toString() : '(anonymous)';
                $issues[] = new Issue(
                    self::RULE,
                    sprintf('Private/protected method %s::%s() has no reference in its own file (possible dead code).', $className, $methodName),
                    $file,
                    $method->getStartLine(),
                    Severity::Info,
                    'custom',
                    ['class' => $className, 'method' => $methodName],
                    Confidence::Low
                );
            }
        }

        return $issues;
    }

    /**
     * Only private/protected, non-magic, non-accessor, non-scope methods are candidates.
     */
    private function isCandidate(Node\Stmt\ClassMethod $method): bool
    {
        if ($method->isPublic() || $method->isAbstract()) {
            return false;
        }

        if ($method->isMagic()) {
            return false;
        }

        $name = $method->name->toString();
        if ($name === '') {
            return false;
        }

        if (str_starts_with($name, '__')) {
            return false;
        }

        // Laravel model accessors (getXAttribute) and query scopes (scopeX).
        if (preg_match('/^get[A-Z].*Attribute$/', $name) === 1) {
            return false;
        }
        if (str_starts_with($name, 'scope') && strlen($name) > 5) {
            return false;
        }

        // Common Laravel lifecycle / serialization / cast methods.
        $lifecycle = [
            'boot', 'booted', 'initialize', 'register', 'provider', 'map',
            'bootIfNotBooted', 'newQuery', 'newEloquentBuilder', 'newBaseQueryBuilder',
            'serialize', 'unserialize', 'jsonSerialize',
        ];

        return !in_array($name, $lifecycle, true);
    }

    private function methodIsReferencedInFile(string $code, string $methodName, int $definitionLine): bool
    {
        $quoted = preg_quote($methodName, '/');
        $patterns = [
            // $this->name(  and  $this->name::...  and  ->name(
            '/(?:->|::)\s*' . $quoted . '\s*\(/',
            '/(?:->|::)\s*' . $quoted . '\s*::/',
        ];

        foreach ($patterns as $pattern) {
            if (preg_match_all($pattern, $code, $matches, PREG_OFFSET_CAPTURE) === 0) {
                continue;
            }
            foreach ($matches[0] as $match) {
                $line = substr_count(substr($code, 0, (int) $match[1]), "\n") + 1;
                if ($line !== $definitionLine) {
                    return true;
                }
            }
        }

        return false;
    }
}
