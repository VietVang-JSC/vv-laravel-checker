<?php

declare(strict_types=1);

namespace VietVang\QualityChecker\Analyzers\Owasp;

use PhpParser\Node;
use VietVang\QualityChecker\Analyzers\AbstractAnalyzer;
use VietVang\QualityChecker\Result\Issue;
use VietVang\QualityChecker\Result\Severity;

/**
 * A03/A04 XML External Entity (XXE).
 *
 * Sinks: simplexml_load_string/file, DOMDocument::load/loadXML, new
 * SimpleXMLElement/XMLReader, and XMLReader::open() (static on the XMLReader
 * class, or ->open() on a reader-named variable).
 * Assumes: any XXE-capable XML sink in a file is reported unless that file also contains a call to
 * libxml_disable_entity_loader(true) or uses the LIBXML_NONET constant. File-level guard detection is
 * a deliberate simplification of the secure-processing intent. Sinks inside test paths are skipped.
 */
final class OwaspXxeAnalyzer extends AbstractAnalyzer
{
    private const RULE = 'OWASP_XXE';

    private const FUNC_SINKS = [
        'simplexml_load_string', 'simplexml_load_file', 'DOMDocument::loadXML', 'DOMDocument::load',
    ];

    private const NEW_SINKS = [
        'SimpleXMLElement', 'XMLReader',
    ];

    public function analyze(array $files): array
    {
        $issues = [];
        foreach ($files as $file) {
            if (!$this->supports($file)) {
                continue;
            }
            if ($this->isTestPath($file)) {
                continue;
            }
            foreach ($this->analyzeFile($file) as $issue) {
                $issues[] = $issue;
            }
        }

        return $issues;
    }

    private function analyzeFile(string $file): array
    {
        $ast = $this->parse($this->readFile($file));
        if ($ast === null) {
            return [];
        }

        if ($this->hasGuard($ast)) {
            return [];
        }

        $issues = [];
        $calls = $this->finder()->find($ast, function (Node $node): bool {
            return $node instanceof Node\Expr\FuncCall
                || $node instanceof Node\Expr\New_
                || $node instanceof Node\Expr\StaticCall
                || $node instanceof Node\Expr\MethodCall;
        });

        foreach ($calls as $call) {
            $sink = $this->resolveSink($call);
            if ($sink === null) {
                continue;
            }

            $issues[] = $this->makeIssue(
                self::RULE,
                sprintf('Potential XXE: XML sink %s used without external entity protection.', $sink),
                $file,
                $call->getStartLine(),
                Severity::Error,
                ['sink' => $sink]
            );
        }

        return $issues;
    }

    private function resolveSink(Node $node): ?string
    {
        if ($node instanceof Node\Expr\FuncCall && $node->name instanceof Node\Name) {
            $fn = $node->name->toString();

            if (in_array($fn, ['simplexml_load_string', 'simplexml_load_file'], true)) {
                return $fn . '()';
            }

            if (in_array($fn, ['load', 'loadXML'], true)) {
                if ($node->args[0] instanceof Node\Arg && $this->isDomDocumentTarget($node->args[0]->value)) {
                    return 'DOMDocument::' . $fn . '()';
                }
            }
        }

        if ($node instanceof Node\Expr\New_ && $node->class instanceof Node\Name) {
            $class = $node->class->toString();
            $lastNewSink = self::NEW_SINKS[count(self::NEW_SINKS) - 1];

            if (
                in_array($class, self::NEW_SINKS, true)
                || str_ends_with($class, '\\' . $lastNewSink)
                || str_ends_with($class, '\\SimpleXMLElement')
            ) {
                return 'new ' . $class . '()';
            }
        }

        // XMLReader::open($uri) / $reader->open($uri): the URI may point at a
        // remote entity source. Receiver-agnostic `->open()` alone is too
        // generic, so method calls require a reader-named variable.
        if (
            $node instanceof Node\Expr\StaticCall
            && $node->class instanceof Node\Name
            && $node->name instanceof Node\Identifier
            && strtolower($node->name->toString()) === 'open'
            && $this->isXmlReaderClass($node->class->toString())
        ) {
            return $node->class->toString() . '::open()';
        }

        if (
            $node instanceof Node\Expr\MethodCall
            && $node->name instanceof Node\Identifier
            && strtolower($node->name->toString()) === 'open'
            && $node->var instanceof Node\Expr\Variable
            && is_string($node->var->name)
            && in_array(strtolower($node->var->name), ['reader', 'xmlreader', 'xml_reader', 'xml'], true)
        ) {
            return 'XMLReader->open()';
        }

        return null;
    }

    private function isXmlReaderClass(string $class): bool
    {
        $normalized = ltrim($class, '\\');

        return $normalized === 'XMLReader' || str_ends_with($normalized, '\\XMLReader');
    }

    private function isDomDocumentTarget(Node\Expr $expr): bool
    {
        if ($expr instanceof Node\Expr\New_ && $expr->class instanceof Node\Name) {
            return $expr->class->toString() === 'DOMDocument' || str_ends_with($expr->class->toString(), '\\DOMDocument');
        }

        if ($expr instanceof Node\Expr\Variable) {
            return in_array($expr->name, ['dom', 'doc', 'domDocument', 'document'], true);
        }

        return false;
    }

    private function hasGuard(array $ast): bool
    {
        $nodes = $this->finder()->find($ast, function (Node $node): bool {
            if (
                $node instanceof Node\Expr\FuncCall
                && $node->name instanceof Node\Name
                && $node->name->toString() === 'libxml_disable_entity_loader'
            ) {
                return true;
            }

            // LIBXML_NONET disables network access (a real guard).
            // LIBXML_NOENT is deliberately NOT a guard: it substitutes
            // entities, which is exactly what enables XXE.
            if (
                $node instanceof Node\Expr\ConstFetch
                && $node->name instanceof Node\Name
                && $node->name->toString() === 'LIBXML_NONET'
            ) {
                return true;
            }

            return false;
        });

        return $nodes !== [];
    }
}
