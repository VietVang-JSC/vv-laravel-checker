<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Analyzers\TestCoverage;

use PhpParser\Node;
use VietVang\QualityChecker\Analyzers\AbstractAnalyzer;
use VietVang\QualityChecker\Result\Confidence;
use VietVang\QualityChecker\Result\Issue;
use VietVang\QualityChecker\Result\Severity;

/**
 * Detect source classes that have no corresponding test.
 *
 * Classifies source files by kind (controller, service, repository, model) and
 * checks whether a matching test exists in the scanned `$files` set — in either
 * `tests/Unit` or `tests/Feature`, and under either the exact mirrored namespace
 * or a flat `*Test.php` convention. Uses the passed `$files` (not the working
 * directory), so it works regardless of the project layout.
 *
 * Heuristic — confidence is low; the check is intentionally conservative to
 * avoid flagging framework/base classes (abstract, enums, interfaces, traits).
 */
final class TestCoverageAnalyzer extends AbstractAnalyzer
{
    private const RULES = [
        'controller' => 'MISSING_CONTROLLER_TEST',
        'service' => 'MISSING_SERVICE_TEST',
        'repository' => 'MISSING_REPOSITORY_TEST',
        'model' => 'MISSING_MODEL_TEST',
        'other' => 'MISSING_UNIT_TEST',
    ];

    /**
     * @param list<string> $files
     * @return Issue[]
     */
    public function analyze(array $files): array
    {
        $tests = $this->indexTests($files);
        $issues = [];

        foreach ($files as $file) {
            if (!$this->supports($file)) {
                continue;
            }
            if ($this->isTestFile($file)) {
                continue;
            }

            foreach ($this->analyzeFile($file, $tests) as $issue) {
                $issues[] = $issue;
            }
        }

        return $issues;
    }

    /**
     * @param array<string, array{namespace: string, class: string}> $tests
     * @return Issue[]
     */
    private function analyzeFile(string $file, array $tests): array
    {
        $ast = $this->parse($this->readFile($file));
        if ($ast === null) {
            return [];
        }

        $issues = [];
        $classes = $this->finder()->findInstanceOf($ast, Node\Stmt\Class_::class);

        foreach ($classes as $class) {
            if (!$class instanceof Node\Stmt\Class_ || $class->name === null) {
                continue;
            }

            [$namespace, $className] = $this->classIdentity($ast, $class);

            $kind = $this->classKind($className);
            if ($kind === null) {
                // Class name doesn't match a known pattern; check if it extends
                // Eloquent\Model (a model) or has a namespace hinting a model.
                $kind = $this->classKindFromExtends($class) ?? $this->classKindFromNamespace($namespace);
            }
            if ($kind === null) {
                continue; // not a class type we track (helper/enum/interface/etc.)
            }

            if ($this->hasTest($namespace, $className, $tests)) {
                continue;
            }

            // Models with no custom logic are rarely unit-tested; skip them to
            // reduce noise unless they carry >= 3 methods.
            if ($kind === 'model' && !$this->classHasLogic($class)) {
                continue;
            }

            $issues[] = $this->makeIssue(
                self::RULES[$kind],
                sprintf(
                    'No %s test found for %s\\%s.',
                    $kind,
                    $namespace,
                    $className
                ),
                $file,
                $class->getStartLine(),
                Severity::Warning,
                ['class' => $className, 'namespace' => $namespace, 'kind' => $kind],
                Confidence::Low
            );
        }

        return $issues;
    }

    private function classKind(string $name): ?string
    {
        if (str_ends_with($name, 'Controller')) {
            return 'controller';
        }
        if (str_ends_with($name, 'Service')) {
            return 'service';
        }
        if (str_ends_with($name, 'Repository')) {
            return 'repository';
        }

        return null;
    }

    private function classKindFromExtends(Node\Stmt\Class_ $class): ?string
    {
        $extends = $class->extends;
        if ($extends !== null && $extends instanceof Node\Name) {
            $name = $extends->toString();
            if (str_ends_with($name, 'Model')) {
                return 'model';
            }
        }

        return null;
    }

    private function classKindFromNamespace(string $namespace): ?string
    {
        if (str_contains($namespace, '\\Models\\') || str_ends_with($namespace, '\\Models')) {
            return 'model';
        }

        return null;
    }

    private function classHasLogic(Node\Stmt\Class_ $class): bool
    {
        $methods = array_filter($class->getMethods(), static fn (Node\Stmt\ClassMethod $m): bool => !$m->isMagic());

        return count($methods) >= 3;
    }

    /**
     * @return array{0: string, 1: string}
     */
    private function classIdentity(array $ast, Node\Stmt\Class_ $class): array
    {
        $namespace = '';
        $namespaces = $this->finder()->findInstanceOf($ast, Node\Stmt\Namespace_::class);
        foreach ($namespaces as $ns) {
            if ($ns instanceof Node\Stmt\Namespace_ && $ns->name !== null) {
                $namespace = $ns->name->toString();
                break;
            }
        }

        return [$namespace, $class->name->toString()];
    }

    /**
     * Index all test files by both their namespace\class and plain basename.
     *
     * @param list<string> $files
     * @return array<string, array{namespace: string, class: string, file: string}>
     */
    private function indexTests(array $files): array
    {
        $tests = [];
        foreach ($files as $file) {
            if (!$this->supports($file) || !$this->isTestFile($file)) {
                continue;
            }

            $ast = $this->parse($this->readFile($file));
            if ($ast === null) {
                continue;
            }

            $classes = $this->finder()->findInstanceOf($ast, Node\Stmt\Class_::class);
            foreach ($classes as $class) {
                if (!$class instanceof Node\Stmt\Class_ || $class->name === null) {
                    continue;
                }
                [$namespace, $className] = $this->classIdentity($ast, $class);

                $key = ltrim($namespace . '\\' . $className, '\\');
                $tests[$key] = ['namespace' => $namespace, 'class' => $className, 'file' => $file];

                // Also index by plain class name for flat test layouts.
                $tests[$className] = ['namespace' => $namespace, 'class' => $className, 'file' => $file];
            }
        }

        return $tests;
    }

    /**
     * @param array<string, array{namespace: string, class: string}> $tests
     */
    private function hasTest(string $namespace, string $className, array $tests): bool
    {
        $testClass = $className . 'Test';

        // Same namespace, class + Test suffix.
        $fq = ltrim($namespace . '\\' . $testClass, '\\');
        if (isset($tests[$fq])) {
            return true;
        }

        // Flat layout: plain basename.
        if (isset($tests[$testClass])) {
            return true;
        }

        // Common alternative: same base name without suffix (e.g. UserTest for model User).
        if (isset($tests[$className])) {
            // Only consider it a hit if that test class maps to a Test-suffixed name elsewhere.
            $candidate = $tests[$className];
            if (str_ends_with($candidate['class'], 'Test') || str_ends_with($candidate['class'], 'TestCase')) {
                return true;
            }
        }

        return false;
    }

    private function isTestFile(string $file): bool
    {
        $normalized = str_replace('\\', '/', $file);

        return str_contains($normalized, '/tests/') || str_starts_with($normalized, 'tests/');
    }
}
