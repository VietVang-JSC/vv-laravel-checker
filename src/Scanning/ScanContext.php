<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Scanning;

use PhpParser\Node;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitor\ParentConnectingVisitor;
use PhpParser\Parser;
use PhpParser\ParserFactory;
use Rampart\QualityChecker\Profiling\Profiler;

/**
 * Scan-owned source + AST cache (PERF-OPT-1). One instance per run,
 * injected into every ScanContextAware analyzer:
 *
 *   read once  → source() serves file text from FileEntry
 *   parse once → ast() serves the node list (or cached failure)
 *
 * Lazy: files no analyzer touches are never read or parsed. One shared
 * Parser instance (factory construction is not the cost — repeated
 * parsing is). Callers must treat returned node lists as READ-ONLY;
 * the mutation audit (ParentConnectingVisitor idempotent markers
 * excepted) guarantees no analyzer rewrites shared trees.
 *
 * CANONICAL AST CONTRACT (PERF-OPT-2): this is the single owner of
 * normal application-source parsing. Every tree served here:
 *
 *   1. Parsed once per file per run (physical parses ≈ unique files).
 *   2. Parent links attached (ParentConnectingVisitor, once).
 *   3. The same tree instance shared across all consumers.
 *   4. Treated as read-only by consumers (no rewrites, no re-linking).
 *   5. Parse failure cached (malformed files never retried).
 *   6. Enrichment performed centrally — a consumer needing more
 *      (NameResolver, symbol IDs, …) must promote it into this
 *      contract, never parse a private tree on the side.
 */
final class ScanContext
{
    /** @var array<string, FileEntry> realpath => entry */
    private array $entries = [];

    private ?Parser $parser = null;

    private int $sourceRequests = 0;

    private int $sourceHits = 0;

    private int $astRequests = 0;

    private int $astHits = 0;

    private int $astMisses = 0;

    private int $parseFailures = 0;

    public function source(string $path): string
    {
        ++$this->sourceRequests;
        $entry = $this->entry($path);
        if ($entry->state !== FileEntry::NOT_LOADED) {
            ++$this->sourceHits;

            return $entry->source;
        }
        Profiler::countRead($path);
        $code = is_file($path) ? file_get_contents($path) : false;
        $entry->source = is_string($code) ? $code : '';
        $entry->state = FileEntry::LOADED;

        return $entry->source;
    }

    /**
     * @return list<Node>|null null = unreadable or unparseable (cached)
     */
    public function ast(string $path): ?array
    {
        ++$this->astRequests;
        $entry = $this->entry($path);
        if ($entry->state === FileEntry::PARSED) {
            ++$this->astHits;

            return $entry->ast;
        }
        if ($entry->state === FileEntry::PARSE_FAILED) {
            ++$this->astHits;

            return null;
        }
        ++$this->astMisses;
        if ($entry->state === FileEntry::NOT_LOADED) {
            $this->source($path);
        }
        if ($entry->source === '') {
            $entry->state = FileEntry::PARSE_FAILED;
            ++$this->parseFailures;

            return null;
        }
        Profiler::countParse($path);
        try {
            $parsed = $this->parser()->parse($entry->source);
        } catch (\Throwable $e) {
            $parsed = null;
        }
        if (!is_array($parsed)) {
            $entry->state = FileEntry::PARSE_FAILED;
            ++$this->parseFailures;

            return null;
        }
        $nodes = [];
        foreach ($parsed as $node) {
            if ($node instanceof Node) {
                $nodes[] = $node;
            }
        }
        // Parent links: InsecureHash/AuthHardening read the 'parent'
        // attribute (their old private parse() attached this visitor),
        // so shared trees carry it — traverser runs once per file.
        $linker = new NodeTraverser();
        $linker->addVisitor(new ParentConnectingVisitor());
        $linker->traverse($nodes);
        $entry->ast = $nodes;
        $entry->state = FileEntry::PARSED;

        return $nodes;
    }

    /**
     * @return array{source_requests: int, source_hits: int, ast_requests: int, ast_hits: int, ast_misses: int, parse_failures: int, files: int}
     */
    public function stats(): array
    {
        return [
            'source_requests' => $this->sourceRequests,
            'source_hits' => $this->sourceHits,
            'ast_requests' => $this->astRequests,
            'ast_hits' => $this->astHits,
            'ast_misses' => $this->astMisses,
            'parse_failures' => $this->parseFailures,
            'files' => count($this->entries),
        ];
    }

    private function entry(string $path): FileEntry
    {
        $real = realpath($path) ?: $path;

        return $this->entries[$real] ??= new FileEntry($real);
    }

    private function parser(): Parser
    {
        return $this->parser ??= (new ParserFactory())->createForNewestSupportedVersion();
    }
}
