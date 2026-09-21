<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Analyzers\TestCoverage;

use PhpParser\Node;
use PhpParser\NodeFinder;
use PhpParser\ParserFactory;
use VietVang\QualityChecker\Result\Issue;
use VietVang\QualityChecker\Result\Severity;

final class ControllerTestAnalyzer
{
    private const RULE = 'MISSING_CONTROLLER_TEST';

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

    private function analyzeControllerFile(string $file, array $featureTests): array
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
                $methodName = $method->name instanceof Node\Identifier ? $method->name->toString() : null;
                if ($methodName === null) {
                    continue;
                }

                if (!$this->methodIsTested($methodName, $testFiles)) {
                    $issues[] = new Issue(
                        self::RULE,
                        sprintf(
                            'Controller method %s::%s() has no asserting Feature test that calls it.',
                            $className ?? '(anonymous)',
                            $methodName
                        ),
                        $file,
                        $method->getStartLine(),
                        Severity::Warning,
                        'custom',
                        ['controller' => $className, 'method' => $methodName]
                    );
                }
            }
        }

        return $issues;
    }

    private function methodIsTested(string $methodName, array $testFiles): bool
    {
        foreach ($testFiles as $body) {
            if (preg_match('/\b' . preg_quote($methodName, '/') . '\b/i', $body) === 1) {
                return true;
            }
        }

        return false;
    }

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
            $result[$path] = $this->readFile($path);
        }

        return $result;
    }

    private function appRoot(): ?string
    {
        foreach ([getcwd(), dirname(__DIR__, 4)] as $candidate) {
            if (is_string($candidate) && is_dir($candidate . '/app')) {
                return $candidate;
            }
        }

        return null;
    }

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
