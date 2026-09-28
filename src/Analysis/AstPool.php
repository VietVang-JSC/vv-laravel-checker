<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Analysis;

use PhpParser\Node;
use PhpParser\NodeFinder;
use PhpParser\ParserFactory;

/**
 * Shared AST pool: parse each file once per run and hand the same AST to
 * every analyzer that opts in (see AstPoolAware). Analyzers that do not
 * opt in keep parsing on their own — both engines coexist.
 *
 * This is the foundation for data-flow work: one parsed representation
 * feeding symbol indexing, Laravel semantics and taint tracking, instead
 * of N independent parses.
 */
final class AstPool
{
    /** @var array<string, list<Node>|null> realpath => AST (null = unreadable/unparseable) */
    private array $cache = [];

    private int $hits = 0;

    private int $misses = 0;

    private NodeFinder $finder;

    public function __construct()
    {
        $this->finder = new NodeFinder();
    }

    /**
     * @return list<Node>|null
     */
    public function ast(string $file): ?array
    {
        $real = realpath($file) ?: $file;
        if (array_key_exists($real, $this->cache)) {
            ++$this->hits;

            return $this->cache[$real];
        }

        ++$this->misses;
        $ast = $this->parseFile($real);
        $this->cache[$real] = $ast;

        return $ast;
    }

    public function finder(): NodeFinder
    {
        return $this->finder;
    }

    public function clear(): void
    {
        $this->cache = [];
        $this->hits = 0;
        $this->misses = 0;
    }

    /**
     * @return array{hits: int, misses: int, files: int}
     */
    public function stats(): array
    {
        return ['hits' => $this->hits, 'misses' => $this->misses, 'files' => count($this->cache)];
    }

    /**
     * @return list<Node>|null
     */
    private function parseFile(string $file): ?array
    {
        if (!is_file($file)) {
            return null;
        }
        $code = file_get_contents($file);
        if (!is_string($code) || $code === '') {
            return null;
        }

        try {
            $parser = (new ParserFactory())->createForNewestSupportedVersion();
            $ast = $parser->parse($code);
        } catch (\Throwable $e) {
            return null;
        }

        if ($ast === null) {
            return null;
        }

        $nodes = [];
        foreach ($ast as $node) {
            if ($node instanceof Node) {
                $nodes[] = $node;
            }
        }

        return $nodes;
    }
}
