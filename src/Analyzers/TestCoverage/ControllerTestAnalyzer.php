<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Analyzers\TestCoverage;

use PhpParser\Node;
use Rampart\QualityChecker\Analysis\CountingNodeFinder;
use Rampart\QualityChecker\Result\Confidence;
use Rampart\QualityChecker\Result\Issue;
use Rampart\QualityChecker\Result\Severity;
use Rampart\QualityChecker\Profiling\Profiler;
use Rampart\QualityChecker\Scanning\ScanContextAware;
use Rampart\QualityChecker\Scanning\ScanContextTrait;

final class ControllerTestAnalyzer implements ScanContextAware
{
    use ScanContextTrait;

    private const RULE = 'MISSING_CONTROLLER_TEST';

    /**
     * @param list<string> $files absolute paths
     * @return list<Issue>
     */
    public function analyze(array $files): array
    {
        $issues = [];
        $featureTests = $this->collectFeatureTestBodies();

        foreach ($files as $file) {
            if (!$this->supports($file)) {
                continue;
            }
            if (!$this->isController($file)) {
                continue;
            }
            foreach ($this->analyzeControllerFile($file, $featureTests) as $issue) {
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
     * @param array<string, string> $featureTests test file path => source
     * @return list<Issue>
     */
    private function analyzeControllerFile(string $file, array $featureTests): array
    {
        $ast = $this->sharedAst($file);
        if ($ast === null) {
            return [];
        }

        $issues = [];
        $finder = new CountingNodeFinder();
        $classes = $finder->findInstanceOf($ast, Node\Stmt\Class_::class);

        $className = null;
        foreach ($classes as $class) {
            $className = $class->name ? $class->name->toString() : null;
            break;
        }

        $testFiles = $this->findControllerTestFiles($file, $featureTests);

        foreach ($classes as $class) {
            foreach ($class->getMethods() as $method) {
                if (!$method->isPublic() || $method->isMagic()) {
                    continue;
                }
                $methodName = $method->name->toString();

                if (!$this->methodIsTested($methodName, $testFiles)) {
                    $issues[] = new Issue(
                        self::RULE,
                        sprintf(
                            'No directly associated asserting Feature test detected for controller method %s::%s().',
                            $className ?? '(anonymous)',
                            $methodName
                        ),
                        $file,
                        $method->getStartLine(),
                        Severity::Info,
                        'custom',
                        ['controller' => $className, 'method' => $methodName],
                        Confidence::Low
                    );
                }
            }
        }

        return $issues;
    }

    /**
     * @param array<string, string> $testFiles test file path => source
     */
    private function methodIsTested(string $methodName, array $testFiles): bool
    {
        foreach ($testFiles as $body) {
            if (preg_match('/\b' . preg_quote($methodName, '/') . '\b/i', $body) === 1) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param array<string, string> $featureTests test file path => source
     * @return array<string, string> matching test file path => source
     */
    private function findControllerTestFiles(string $controllerFile, array $featureTests): array
    {
        $base = pathinfo($controllerFile, PATHINFO_FILENAME);
        $candidates = [
            $base . 'Test.php',
            'Controllers\\' . $base . 'Test.php',
            'Http\\Controllers\\' . $base . 'Test.php',
        ];

        $matches = [];
        foreach ($featureTests as $testFile => $body) {
            foreach ($candidates as $candidate) {
                $candidateBase = '\\' . str_replace('\\', '/', $candidate);
                if (
                    str_ends_with(str_replace('\\', '/', $testFile), $candidateBase)
                    || str_ends_with($testFile, '/' . $candidate)
                    || $testFile === $candidate
                ) {
                    $matches[$testFile] = $body;
                    break;
                }
            }
        }

        return $matches;
    }

    private function isController(string $file): bool
    {
        $normalized = str_replace('\\', '/', $file);

        return str_contains($normalized, '/Controllers/') && str_ends_with($normalized, 'Controller.php');
    }

    /**
     * @return array<string, string> test file path => source
     */
    private function collectFeatureTestBodies(): array
    {
        $result = [];
        $root = $this->appRoot();
        if ($root === null) {
            return $result;
        }

        $dir = $root . '/tests/Feature';
        if (!is_dir($dir)) {
            return $result;
        }

        foreach ($this->listPhpFiles($dir) as $path) {
            $result[$path] = $this->sharedSource($path);
        }

        return $result;
    }

    private function appRoot(): ?string
    {
        $root = $this->scanRoot();
        if ($root === null) {
            return null;
        }

        return is_dir($root . '/app') || is_dir($root . '/routes') ? $root : null;
    }

    /**
     * @return list<string>
     */
    private function listPhpFiles(string $dir): array
    {
        $files = [];
        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS)
        );
        foreach ($iterator as $file) {
            if ($file instanceof \SplFileInfo && $file->isFile() && $file->getExtension() === 'php') {
                $files[] = $file->getPathname();
            }
        }

        return $files;
    }
}
