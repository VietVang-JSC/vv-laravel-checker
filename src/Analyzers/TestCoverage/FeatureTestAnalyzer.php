<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Analyzers\TestCoverage;

use PhpParser\Node;
use PhpParser\NodeFinder;
use PhpParser\ParserFactory;
use VietVang\QualityChecker\Result\Issue;
use VietVang\QualityChecker\Result\Severity;

final class FeatureTestAnalyzer
{
    private const RULE = 'MISSING_FEATURE_COVERAGE';

    public function analyze(array $files): array
    {
        $issues = [];
        $featureTests = $this->collectFeatureTestBodies();
        $routes = $this->collectRoutes();

        foreach ($routes as $route) {
            if ($this->routeIsCovered($route, $featureTests)) {
                continue;
            }

            $issues[] = new Issue(
                self::RULE,
                sprintf(
                    'Route [%s %s -> %s] has no Feature test that references its URI or calls its action.',
                    $route['method'],
                    $route['uri'],
                    $route['action']
                ),
                $route['file'],
                $route['line'],
                Severity::Info,
                'custom',
                ['method' => $route['method'], 'uri' => $route['uri'], 'action' => $route['action']]
            );
        }

        return $issues;
    }

    public function supports(string $path): bool
    {
        return strtolower((string) pathinfo($path, PATHINFO_EXTENSION)) === 'php';
    }

    private function routeIsCovered(array $route, array $featureTests): bool
    {
        foreach ($featureTests as $body) {
            $uri = trim($route['uri'], '/');
            if ($uri !== '' && $uri !== '/' && str_contains($body, $uri)) {
                return true;
            }
            if (str_contains($body, $route['uri'])) {
                return true;
            }

            $actionMethod = $this->actionMethod($route['action']);
            if ($actionMethod !== null && preg_match('/\b' . preg_quote($actionMethod, '/') . '\b/i', $body) === 1) {
                return true;
            }
        }

        return false;
    }

    private function collectRoutes(): array
    {
        $routes = [];
        $root = $this->appRoot();
        if ($root === null) {
            return $routes;
        }

        $dir = $root . '/routes';
        if (!is_dir($dir)) {
            return $routes;
        }

        foreach ($this->listPhpFiles($dir) as $path) {
            $code = $this->readFile($path);
            if ($code === '') {
                continue;
            }
            foreach ($this->parseRoutesFromSource($path, $code) as $route) {
                $routes[] = $route;
            }
        }

        return $routes;
    }

    private function parseRoutesFromSource(string $file, string $code): array
    {
        $routes = [];

        $regex = '/\b(?:Route|db_seed|web|api)::(get|post|put|patch|delete|options|any)\s*\(\s*([\'"])(.*?)\2\s*,\s*([\'"])(.*?)\5/s';
        if (preg_match_all($regex, $code, $matches, PREG_SET_ORDER) === false) {
            return $routes;
        }

        foreach ($matches as $m) {
            $routes[] = [
                'method' => strtoupper($m[1]),
                'uri' => $m[3],
                'action' => $m[5],
                'file' => $file,
                'line' => $this->lineOfSubstring($code, $m[0]),
            ];
        }

        return $routes;
    }

    private function actionMethod(string $action): ?string
    {
        if (str_contains($action, '@')) {
            return substr($action, strrpos($action, '@') + 1);
        }

        if (str_contains($action, '::')) {
            return substr($action, strrpos($action, '::') + 1);
        }

        return null;
    }

    private function lineOfSubstring(string $code, string $substring): int
    {
        $pos = strpos($code, $substring);
        if ($pos === false) {
            return 0;
        }

        return substr_count(substr($code, 0, $pos), "\n") + 1;
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
}
