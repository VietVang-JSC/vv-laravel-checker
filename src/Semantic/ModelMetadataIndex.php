<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Semantic;

use PhpParser\Node;
use PhpParser\NodeFinder;
use Rampart\QualityChecker\Scanning\ScanContextAware;
use Rampart\QualityChecker\Scanning\ScanContextTrait;

/**
 * Model class map with global unguard state. Bounded: model files are
 * located under the configured model directories (default `app/Models`);
 * classes are keyed by FQCN and short name.
 *
 * Global unguard is true when any non-seed scanned file calls
 * `::unguard()` (with an argument other than `false`) and no file calls
 * `::reguard()`. Scoped `unguarded(callback)` never flips global state.
 */
final class ModelMetadataIndex implements ScanContextAware
{
    use ScanContextTrait;

    /** @var list<string> */
    private array $modelDirSegments;

    /** @var array<string, string> class name (FQCN and short) => file */
    private array $modelFiles = [];

    private bool $globallyUnguarded = false;

    /**
     * @param list<string> $files
     * @param string|list<string>|null $modelsDirs
     */
    public function __construct(array $files = [], $modelsDirs = null)
    {
        $raw = $modelsDirs ?? ['app/Models'];
        if (is_string($raw)) {
            $raw = [$raw];
        }
        $segments = [];
        foreach ((array) $raw as $dir) {
            if (!is_string($dir)) {
                continue;
            }
            $seg = trim(str_replace('\\', '/', $dir), '/');
            if ($seg !== '') {
                $segments[] = $seg;
            }
        }
        $this->modelDirSegments = $segments !== [] ? array_values(array_unique($segments)) : ['app/Models'];
        if ($files !== []) {
            $this->build($files);
        }
    }

    /**
     * @param list<string> $files
     */
    public function build(array $files): self
    {
        $sawUnguard = false;
        $sawReguard = false;
        foreach ($files as $file) {
            if (strtolower((string) pathinfo($file, PATHINFO_EXTENSION)) !== 'php') {
                continue;
            }
            if ($this->inModelDir($file)) {
                $this->collectModelFile($file);
            }
            [$unguarded, $reguarded] = $this->scanUnguard($file);
            $sawUnguard = $sawUnguard || $unguarded;
            $sawReguard = $sawReguard || $reguarded;
        }
        $this->globallyUnguarded = $sawUnguard && !$sawReguard;

        return $this;
    }

    public function metadataFor(string $model): ?ModelMetadata
    {
        $key = ltrim($model, '\\');
        $file = $this->modelFiles[$key] ?? $this->modelFiles[$this->shortClass($key)] ?? null;
        if ($file === null) {
            return null;
        }

        return ModelMetadata::fromFile($key, $file, $this->sharedScanContext());
    }

    public function globallyUnguarded(): bool
    {
        return $this->globallyUnguarded;
    }

    private function inModelDir(string $file): bool
    {
        $pathname = str_replace('\\', '/', $file);
        foreach ($this->modelDirSegments as $seg) {
            if (stripos($pathname, '/' . $seg . '/') !== false) {
                return true;
            }
        }

        return false;
    }

    private function collectModelFile(string $file): void
    {
        $code = $this->sharedSource($file);
        if ($code === '') {
            return;
        }
        $ast = $this->sharedAst($file);
        if ($ast === null) {
            return;
        }
        $finder = new NodeFinder();
        $class = $finder->findFirstInstanceOf($ast, Node\Stmt\Class_::class);
        if ($class === null || $class->name === null) {
            return;
        }
        $namespace = $finder->findFirstInstanceOf($ast, Node\Stmt\Namespace_::class);
        $prefix = $namespace !== null && $namespace->name !== null ? $namespace->name->toString() : '';
        $fqcn = $prefix !== '' ? $prefix . '\\' . $class->name->toString() : $class->name->toString();
        $this->modelFiles[$fqcn] = $file;
        $this->modelFiles[$class->name->toString()] = $file;
    }

    /**
     * @return array{bool, bool} [unguarded, reguarded]
     */
    private function scanUnguard(string $file): array
    {
        if ($this->isSeedDataPath($file)) {
            return [false, false];
        }
        $code = $this->sharedSource($file);
        if ($code === '') {
            return [false, false];
        }
        $ast = $this->sharedAst($file);
        if ($ast === null) {
            return [false, false];
        }
        $finder = new NodeFinder();
        $calls = $finder->find($ast, static function (Node $node): bool {
            return $node instanceof Node\Expr\StaticCall && $node->name instanceof Node\Identifier;
        });
        $unguarded = false;
        $reguarded = false;
        foreach ($calls as $call) {
            if (!$call instanceof Node\Expr\StaticCall || !$call->name instanceof Node\Identifier) {
                continue;
            }
            $name = strtolower($call->name->toString());
            if ($name === 'reguard') {
                $reguarded = true;
            }
            if ($name !== 'unguard' || !$call->class instanceof Node\Name) {
                continue;
            }
            $state = $call->args[0] ?? null;
            if (
                $state instanceof Node\Arg
                && $state->value instanceof Node\Expr\ConstFetch
                && strtolower($state->value->name->toString()) === 'false'
            ) {
                continue;
            }
            $unguarded = true;
        }

        return [$unguarded, $reguarded];
    }

    private function isSeedDataPath(string $file): bool
    {
        $normalized = strtolower(str_replace('\\', '/', $file));

        return str_contains($normalized, '/database/seeders/')
            || str_contains($normalized, '/database/factories/')
            || str_contains($normalized, '/database/migrations/')
            || str_contains($normalized, '/tests/')
            || str_starts_with($normalized, 'tests/');
    }

    private function shortClass(string $class): string
    {
        $trimmed = ltrim($class, '\\');
        $pos = strrpos($trimmed, '\\');

        return $pos === false ? $trimmed : substr($trimmed, $pos + 1);
    }
}
