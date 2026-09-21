<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Analyzers\Security;

use PhpParser\Node;
use PhpParser\NodeFinder;
use PhpParser\ParserFactory;
use PhpParser\PrettyPrinter\Standard;
use VietVang\QualityChecker\Result\Issue;
use VietVang\QualityChecker\Result\Severity;

final class MassAssignmentAnalyzer
{
    private const RULE = 'MASS_ASSIGNMENT';

    private const SOURCE_METHODS = [
        'create',
        'insert',
        'update',
        'fill',
    ];

    public function analyze(array $files): array
    {
        $issues = [];
        $modelClassFiles = $this->findModelClassFiles($files);
        foreach ($files as $file) {
            if (!$this->supports($file)) {
                continue;
            }
            foreach ($this->analyzeFile($file, $modelClassFiles) as $issue) {
                $issues[] = $issue;
            }
        }

        return $issues;
    }

    public function supports(string $path): bool
    {
        return strtolower((string) pathinfo($path, PATHINFO_EXTENSION)) === 'php';
    }

    public function analyzeFile(string $file, array $modelClassFiles = []): array
    {
        $code = $this->readFile($file);
        if ($code === '') {
            return [];
        }

        $ast = $this->parse($code);
        if ($ast === null) {
            return [];
        }

        if ($modelClassFiles === []) {
            $modelClassFiles = $this->findModelClassFiles([$file]);
        }

        return $this->findIssues($file, $ast, $modelClassFiles);
    }

    private function findIssues(string $file, array $ast, array $modelClassFiles): array
    {
        $issues = [];
        $finder = new NodeFinder();
        $printer = new Standard();

        $calls = $finder->find($ast, function (Node $node): bool {
            if (!$node instanceof Node\Expr\StaticCall && !$node instanceof Node\Expr\MethodCall) {
                return false;
            }

            $method = $node->name instanceof Node\Identifier ? $node->name->toString() : null;

            return $method !== null && in_array($method, self::SOURCE_METHODS, true);
        });

        foreach ($calls as $call) {
            $method = $call->name instanceof Node\Identifier ? $call->name->toString() : '';
            $args = is_array($call->args ?? null) ? $call->args : [];
            if (count($args) === 0) {
                continue;
            }

            $firstArg = $args[0]->value;
            if (!$this->isRequestInput($firstArg)) {
                continue;
            }

            $target = $this->resolveModelTarget($call);
            if ($target === null) {
                continue;
            }

            if (!$this->modelExists($target, $modelClassFiles)) {
                continue;
            }

            if ($this->modelDefinesMassAssignmentGuard($target, $modelClassFiles)) {
                continue;
            }

            $issues[] = new Issue(
                self::RULE,
                sprintf(
                    'Model::%s() called with untrusted request input (%s) but no $fillable/$guarded is defined.',
                    $method,
                    $printer->prettyPrintExpr($firstArg)
                ),
                $file,
                $call->getStartLine(),
                Severity::Error,
                'custom',
                ['method' => $method, 'model' => $target]
            );
        }

        return $issues;
    }

    private function resolveModelTarget(Node $call): ?string
    {
        if ($call instanceof Node\Expr\StaticCall && $call->class instanceof Node\Name) {
            return $call->class->toString();
        }

        return null;
    }

    private function modelExists(string $model, array $modelClassFiles): bool
    {
        return isset($modelClassFiles[$model]);
    }

    private function modelDefinesMassAssignmentGuard(string $model, array $modelClassFiles): bool
    {
        if (!isset($modelClassFiles[$model])) {
            return false;
        }

        $code = $this->readFile($modelClassFiles[$model]);
        if ($code === '') {
            return false;
        }

        $ast = $this->parse($code);
        if ($ast === null) {
            return false;
        }

        $finder = new NodeFinder();
        $properties = $finder->findInstanceOf($ast, Node\Stmt\Property::class);

        foreach ($properties as $property) {
            if (!$property->isProtected() && !$property->isPublic()) {
                continue;
            }
            foreach ($property->props as $prop) {
                if ($prop->name instanceof Node\Identifier) {
                    $name = $prop->name->toString();
                    if ($name === 'fillable' || $name === 'guarded') {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * @param list<string> $files
     * @return array<string, string> class name (FQCN or short name) => file path
     */
    private function findModelClassFiles(array $files): array
    {
        $result = [];
        foreach ($files as $file) {
            $pathname = str_replace('\\', '/', $file);
            if (stripos($pathname, '/app/Models/') === false) {
                continue;
            }

            [$fqcn, $short] = $this->resolveClassName($file);
            if ($fqcn === null) {
                continue;
            }

            $result[$fqcn] = $file;
            if ($short !== null) {
                $result[$short] = $file;
            }
        }

        return $result;
    }

    /**
     * @return array{string, string|null} [FQCN, short name]
     */
    private function resolveClassName(string $path): array
    {
        $code = $this->readFile($path);
        if ($code === '') {
            return [null, null];
        }
        $ast = $this->parse($code);
        if ($ast === null) {
            return [null, null];
        }

        $finder = new NodeFinder();
        $class = $finder->findFirstInstanceOf($ast, Node\Stmt\Class_::class);
        if ($class === null || $class->name === null) {
            return [null, null];
        }

        $namespace = $finder->findFirstInstanceOf($ast, Node\Stmt\Namespace_::class);
        $prefix = $namespace !== null && $namespace->name !== null ? $namespace->name->toString() : '';
        $fqcn = $prefix !== '' ? $prefix . '\\' . $class->name->toString() : $class->name->toString();

        return [$fqcn, $class->name->toString()];
    }

    private function isRequestInput(Node\Expr $expr): bool
    {
        if (!$expr instanceof Node\Expr\MethodCall) {
            return false;
        }

        $method = $expr->name instanceof Node\Identifier ? $expr->name->toString() : null;
        if (!in_array($method, ['all', 'except', 'only'], true)) {
            return false;
        }

        $var = $expr->var;
        if ($var instanceof Node\Expr\Variable && $var->name === 'request') {
            return true;
        }

        if (
            $var instanceof Node\Expr\PropertyFetch
            && $var->name instanceof Node\Identifier
            && $var->name->toString() === 'request'
            && $var->var instanceof Node\Expr\Variable
            && $var->var->name === 'this'
        ) {
            return true;
        }

        return false;
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
