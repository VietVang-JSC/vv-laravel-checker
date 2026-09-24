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
                || $node instanceof Node\Expr\New_;
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
            $lastNewSink = (string) (array_values(self::NEW_SINKS)[array_key_last(self::NEW_SINKS)] ?? '');

            if (
                in_array($class, self::NEW_SINKS, true)
                || str_ends_with($class, '\\' . $lastNewSink)
                || str_ends_with($class, '\\SimpleXMLElement')
            ) {
                return 'new ' . $class . '()';
            }
        }

        return null;
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

            if (
                $node instanceof Node\Expr\ConstFetch
                && $node->name instanceof Node\Name
                && in_array($node->name->toString(), ['LIBXML_NONET', 'LIBXML_NOENT'], true)
            ) {
                return true;
            }

            return false;
        });

        return $nodes !== [];
    }
}
