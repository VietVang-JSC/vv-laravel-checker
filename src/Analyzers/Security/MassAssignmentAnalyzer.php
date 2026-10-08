<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Analyzers\Security;

use PhpParser\Node;
use Rampart\QualityChecker\Analysis\CountingNodeFinder;
use PhpParser\PrettyPrinter\Standard;
use Rampart\QualityChecker\Analysis\ScopeIds;
use Rampart\QualityChecker\Analysis\ScopeResolver;
use Rampart\QualityChecker\Analysis\StructuralFactIndex;
use Rampart\QualityChecker\Result\Confidence;
use Rampart\QualityChecker\Result\Issue;
use Rampart\QualityChecker\Result\Severity;
use Rampart\QualityChecker\Scanning\ScanContextAware;
use Rampart\QualityChecker\Scanning\ScanContextTrait;
use Rampart\QualityChecker\Semantic\MassAssignmentDecision;
use Rampart\QualityChecker\Semantic\MassAssignmentFlow;
use Rampart\QualityChecker\Semantic\MassFlow;
use Rampart\QualityChecker\Semantic\ModelMetadata;
use Rampart\QualityChecker\Semantic\ModelMetadataIndex;
use Rampart\QualityChecker\Semantic\ModelTypeResolver;
use Rampart\QualityChecker\Profiling\Profiler;

final class MassAssignmentAnalyzer implements ScanContextAware
{
    use ScanContextTrait;

    private const RULE = 'MASS_ASSIGNMENT';

    /** @var list<string> normalized model dir segments (e.g. app/Models) */
    private array $modelDirSegments = ['app/Models'];

    private ?StructuralFactIndex $facts = null;

    /**
     * Shared structural facts for this run (one indexing traversal per
     * file). Scope/dataflow questions still go through ScopeResolver,
     * MassAssignmentFlow and the metadata index.
     */
    private function facts(): StructuralFactIndex
    {
        if ($this->facts === null) {
            $this->facts = new StructuralFactIndex();
            $this->facts->setScanContext($this->sharedScanContext());
        }

        return $this->facts;
    }

    /**
     * @param array{models_dirs?: string|list<string>} $options
     */
    public function __construct(array $options = [])
    {
        $raw = $options['models_dirs'] ?? ['app/Models'];
        if (is_string($raw)) {
            $raw = [$raw];
        }
        $segments = [];
        foreach ($raw as $dir) {
            if (!is_string($dir)) {
                continue;
            }
            $seg = trim(str_replace('\\', '/', $dir), '/');
            if ($seg !== '') {
                $segments[] = $seg;
            }
        }
        if ($segments !== []) {
            $this->modelDirSegments = array_values(array_unique($segments));
        }
    }

    private const SOURCE_METHODS = [
        'create',
        'insert',
        'update',
        'fill',
        'updateOrCreate',
        'firstOrCreate',
        'updateOrInsert',
        'firstOrNew',
    ];

    /**
     * @param list<string> $files absolute paths
     * @return list<Issue>
     */
    public function analyze(array $files): array
    {
        $issues = [];
        $modelClassFiles = $this->findModelClassFiles($files);
        $metaIndex = new ModelMetadataIndex([], $this->modelDirSegments);
        $metaIndex->setScanContext($this->sharedScanContext());
        Profiler::begin('semantic-index');
        $metaIndex->build($files);
        Profiler::end('semantic-index');
        foreach ($files as $file) {
            if (!$this->supports($file)) {
                continue;
            }
            foreach ($this->analyzeFile($file, $modelClassFiles, $metaIndex) as $issue) {
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
     * @param array<string, string> $modelClassFiles class name => file path
     * @return list<Issue>
     */
    public function analyzeFile(string $file, array $modelClassFiles = [], ?ModelMetadataIndex $metaIndex = null): array
    {
        $ast = $this->sharedAst($file);
        if ($ast === null) {
            return [];
        }

        if ($modelClassFiles === []) {
            $modelClassFiles = $this->findModelClassFiles([$file]);
        }
        if ($metaIndex === null) {
            $metaIndex = new ModelMetadataIndex([], $this->modelDirSegments);
            $metaIndex->setScanContext($this->sharedScanContext());
            $metaIndex->build([$file]);
        }

        return $this->findIssues($file, $ast, $modelClassFiles, $metaIndex);
    }

    /**
     * @param list<Node> $ast
     * @param array<string, string> $modelClassFiles class name => file path
     * @return list<Issue>
     */
    private function findIssues(
        string $file,
        array $ast,
        array $modelClassFiles,
        ModelMetadataIndex $metaIndex
    ): array {
        $issues = [];
        $finder = new CountingNodeFinder();
        $printer = new Standard();
        $scopes = new ScopeResolver($finder);
        // Structural facts (one indexed pass): same sets and order the
        // direct finds returned — scope/dataflow logic below untouched.
        $funcs = [];
        foreach ($this->facts()->functions($file, $ast) as $func) {
            $funcs[spl_object_id($func)] = $func;
        }
        $uses = $this->useMap($file, $ast);
        $namespace = $this->namespaceOf($file, $ast);

        /** @var list<Node\Expr> $calls (widened: downstream guards re-check the shape) */
        $calls = [];
        foreach ($this->facts()->calls($file, $ast) as $call) {
            if (!$call instanceof Node\Expr\StaticCall && !$call instanceof Node\Expr\MethodCall) {
                continue;
            }

            $method = $call->name instanceof Node\Identifier ? $call->name->toString() : null;
            if ($method !== null && ($method === 'unguard' || $method === 'forceFill' || $method === 'forceCreate' || in_array($method, self::SOURCE_METHODS, true))) {
                $calls[] = $call;
            }
        }

        foreach ($calls as $call) {
            // Shape re-verified: discovery is a prefilter, downstream
            // logic owns the type contract (also keeps phpstan sound).
            if (!$call instanceof Node\Expr\StaticCall && !$call instanceof Node\Expr\MethodCall) {
                continue;
            }
            $method = $call->name instanceof Node\Identifier ? $call->name->toString() : '';
            $args = is_array($call->args ?? null) ? $call->args : [];

            if ($method === 'unguard' && $call instanceof Node\Expr\StaticCall && $this->isUnguardedModel($call, $file, $ast, $modelClassFiles)) {
                $state = $call->args[0] ?? null;
                if (
                    $state instanceof Node\Arg
                    && $state->value instanceof Node\Expr\ConstFetch
                    && strtolower($state->value->name->toString()) === 'false'
                ) {
                    continue;
                }
                // Seed data paths (seeders, data migrations, tests) carry no
                // request input by construction — unguard() there seeds
                // literals. Console commands and jobs keep flagging: CLI
                // arguments and job payloads are real input.
                if ($this->isSeedDataPath($file)) {
                    continue;
                }
                $issues[] = new Issue(
                    self::RULE,
                    'Mass assignment protection is disabled globally via Model::unguard() — every attribute becomes fillable.',
                    $file,
                    $call->getStartLine(),
                    Severity::Error,
                    'custom',
                    ['method' => $method]
                );
                continue;
            }

            // forceFill()/forceCreate() bypass $fillable/$guarded by design.
            // Decision-first; the legacy fallback below preserves the exact
            // old behavior (direct request input only; literals silent).
            // ($call shape already verified at loop head.)
            if ($method === 'forceFill' || $method === 'forceCreate') {
                $this->checkForceCall($call, $args, $method, $ast, $funcs, $scopes, $uses, $namespace, $file, $metaIndex, $issues);
                continue;
            }
            $this->checkMassCall(
                $call,
                $args,
                $method,
                $ast,
                $funcs,
                $scopes,
                $uses,
                $namespace,
                $file,
                $metaIndex,
                $modelClassFiles,
                $printer,
                $issues
            );
        }

        return $issues;
    }

    /**
     * @param list<Node\Arg|Node\VariadicPlaceholder> $args
     * @param list<Node> $ast
     * @param array<int, Node\Stmt\ClassMethod|Node\Stmt\Function_> $funcs
     * @param array<string, string> $uses
     * @param Issue[] $issues
     */
    private function checkForceCall(
        Node\Expr $call,
        array $args,
        string $method,
        array $ast,
        array $funcs,
        ScopeResolver $scopes,
        array $uses,
        ?string $namespace,
        string $file,
        ModelMetadataIndex $metaIndex,
        array &$issues
    ): void {
        if (!($call instanceof Node\Expr\StaticCall || $call instanceof Node\Expr\MethodCall)) {
            return;
        }
        $firstArg = $args[0] ?? null;
        if ($firstArg instanceof Node\Arg) {
            $decision = $this->decideSink($call, $firstArg->value, $method, $ast, $funcs, $scopes, $uses, $namespace, $file, $metaIndex);
            if ($decision instanceof MassAssignmentDecision) {
                // Shadow-pool signal for PERF-OPT-3B equivalence (profile-only).
                Profiler::countDecision('MassAssignmentAnalyzer', $decision->verdict);
                if ($decision->verdict === MassAssignmentDecision::SAFE) {
                    return;
                }
                if (
                    $decision->verdict === MassAssignmentDecision::EXPOSED
                    || $decision->verdict === MassAssignmentDecision::REVIEW
                ) {
                    $issues[] = $this->decisionIssue($decision, $method, $file, $call->getStartLine());

                    return;
                }
            }
        }
        // Legacy fallback (byte-identical): direct request input only.
        if ($method !== 'forceFill') {
            return;
        }
        if ($firstArg instanceof Node\Arg && $this->isRequestInput($firstArg->value)) {
            $issues[] = new Issue(
                self::RULE,
                'forceFill() with untrusted request input bypasses mass assignment protection ($fillable/$guarded are ignored) — use fill() with $fillable or validated().',
                $file,
                $call->getStartLine(),
                Severity::Error,
                'custom',
                [
                    'method' => $method,
                    'flow_provenance' => $this->flowProvenance(
                        $call,
                        $firstArg->value,
                        $method,
                        $ast,
                        $funcs,
                        $scopes,
                        $file
                    ),
                ]
            );
        }
    }

    /**
     * Decision-first for create/fill/update/... sinks. SAFE suppresses
     * (with evidence); EXPOSED/REVIEW emit production findings with the
     * full chain payload; UNKNOWN/INTERNAL fall back to the byte-identical
     * legacy heuristic below.
     *
     * @param list<Node\Arg|Node\VariadicPlaceholder> $args
     * @param list<Node> $ast
     * @param array<int, Node\Stmt\ClassMethod|Node\Stmt\Function_> $funcs
     * @param array<string, string> $uses
     * @param array<string, string> $modelClassFiles
     * @param Issue[] $issues
     */
    private function checkMassCall(
        Node\Expr $call,
        array $args,
        string $method,
        array $ast,
        array $funcs,
        ScopeResolver $scopes,
        array $uses,
        ?string $namespace,
        string $file,
        ModelMetadataIndex $metaIndex,
        array $modelClassFiles,
        Standard $printer,
        array &$issues
    ): void {
        if (!($call instanceof Node\Expr\StaticCall || $call instanceof Node\Expr\MethodCall)) {
            return;
        }
        $decision = $this->decideCall($call, $args, $method, $ast, $funcs, $scopes, $uses, $namespace, $file, $metaIndex);
        if ($decision instanceof MassAssignmentDecision) {
            // Shadow-pool signal for PERF-OPT-3B equivalence (profile-only).
            Profiler::countDecision('MassAssignmentAnalyzer', $decision->verdict);
            if ($decision->verdict === MassAssignmentDecision::SAFE) {
                return;
            }
            if (
                $decision->verdict === MassAssignmentDecision::EXPOSED
                || $decision->verdict === MassAssignmentDecision::REVIEW
            ) {
                $issues[] = $this->decisionIssue($decision, $method, $file, $call->getStartLine());

                return;
            }
        }

        // Legacy fallback (byte-identical findings).
        if (count($args) === 0) {
            return;
        }

        $first = $args[0] ?? null;
        if (!$first instanceof Node\Arg) {
            return;
        }
        $firstArg = $first->value;
        if (!$this->isRequestInput($firstArg)) {
            // updateOr*/firstOr* take lookup attributes first and fill values
            // second — taint in either argument is mass assignment.
            if (!in_array($method, ['updateOrCreate', 'firstOrCreate', 'updateOrInsert', 'firstOrNew'], true)) {
                return;
            }
            $tainted = false;
            foreach (array_slice($args, 1) as $extra) {
                if ($extra instanceof Node\Arg && $this->isRequestInput($extra->value)) {
                    $tainted = true;
                    break;
                }
            }
            if (!$tainted) {
                return;
            }
        }

        $target = $this->resolveModelTarget($call);
        if ($target === null) {
            return;
        }

        if (!$this->modelExists($target, $modelClassFiles)) {
            return;
        }

        if ($this->modelDefinesMassAssignmentGuard($target, $modelClassFiles)) {
            return;
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
            [
                'method' => $method,
                'model' => $target,
                'flow_provenance' => $this->flowProvenance(
                    $call,
                    $this->taintingArg($call, $args, $method),
                    $method,
                    $ast,
                    $funcs,
                    $scopes,
                    $file
                ),
            ]
        );
    }

    /**
     * Decision-first classification for one sink call. Returns null when
     * no method context exists (legacy path decides).
     *
     * @param list<Node\Arg|Node\VariadicPlaceholder> $args
     * @param list<Node> $ast
     * @param array<int, Node\Stmt\ClassMethod|Node\Stmt\Function_> $funcs
     * @param array<string, string> $uses
     */
    private function decideCall(
        Node\Expr\StaticCall|Node\Expr\MethodCall $call,
        array $args,
        string $method,
        array $ast,
        array $funcs,
        ScopeResolver $scopes,
        array $uses,
        ?string $namespace,
        string $file,
        ModelMetadataIndex $metaIndex
    ): ?MassAssignmentDecision {
        $funcId = ScopeIds::outermost($call);
        $func = $funcs[$funcId] ?? null;
        if (!$func instanceof Node\Stmt\ClassMethod) {
            return null;
        }
        $candidates = [];
        $first = $args[0] ?? null;
        if ($first instanceof Node\Arg) {
            $candidates[] = $first->value;
        }
        if (in_array($method, ['updateOrCreate', 'firstOrCreate', 'updateOrInsert', 'firstOrNew'], true)) {
            foreach (array_slice($args, 1) as $extra) {
                if ($extra instanceof Node\Arg) {
                    $candidates[] = $extra->value;
                }
            }
        }
        $picked = null;
        foreach ($candidates as $candidate) {
            $flow = MassAssignmentFlow::classify(
                $candidate,
                $method,
                $func,
                $ast,
                $funcId,
                $file,
                $call->getStartLine()
            );
            if ($flow->status !== MassFlow::INTERNAL) {
                $picked = $flow;
                break;
            }
        }
        if ($picked === null) {
            return null;
        }
        $model = $this->resolveSinkModel($call, $func, $uses, $namespace);
        $meta = $model !== null ? $metaIndex->metadataFor($model) : null;

        return MassAssignmentDecision::decide($picked, $meta, $metaIndex->globallyUnguarded());
    }

    /**
     * Decision-first for forceFill()/forceCreate() (single argument).
     *
     * @param list<Node> $ast
     * @param array<int, Node\Stmt\ClassMethod|Node\Stmt\Function_> $funcs
     * @param array<string, string> $uses
     */
    private function decideSink(
        Node\Expr\StaticCall|Node\Expr\MethodCall $call,
        Node\Expr $arg,
        string $method,
        array $ast,
        array $funcs,
        ScopeResolver $scopes,
        array $uses,
        ?string $namespace,
        string $file,
        ModelMetadataIndex $metaIndex
    ): ?MassAssignmentDecision {
        $funcId = ScopeIds::outermost($call);
        $func = $funcs[$funcId] ?? null;
        if (!$func instanceof Node\Stmt\ClassMethod) {
            return null;
        }
        $flow = MassAssignmentFlow::classify($arg, $method, $func, $ast, $funcId, $file, $call->getStartLine());
        $model = $this->resolveSinkModel($call, $func, $uses, $namespace);
        $meta = $model !== null ? $metaIndex->metadataFor($model) : null;

        return MassAssignmentDecision::decide($flow, $meta, $metaIndex->globallyUnguarded());
    }

    /**
     * @param array<string, string> $uses
     */
    private function resolveSinkModel(
        Node\Expr\StaticCall|Node\Expr\MethodCall $call,
        Node\Stmt\ClassMethod $func,
        array $uses,
        ?string $namespace
    ): ?string {
        if ($call instanceof Node\Expr\StaticCall && $call->class instanceof Node\Name) {
            return $this->resolveName($call->class->toString(), $uses, $namespace);
        }
        if (
            $call instanceof Node\Expr\MethodCall
            && $call->var instanceof Node\Expr\Variable
            && is_string($call->var->name)
        ) {
            return ModelTypeResolver::resolve($call->var, $func, $uses, $namespace, $call->getStartLine());
        }

        return null;
    }

    /**
     * @param array<string, string> $uses
     */
    private function resolveName(string $name, array $uses, ?string $namespace): string
    {
        if (str_starts_with($name, '\\')) {
            return ltrim($name, '\\');
        }
        $pos = strpos($name, '\\');
        if ($pos !== false) {
            $first = strtolower(substr($name, 0, $pos));
            if (isset($uses[$first])) {
                return $uses[$first] . substr($name, $pos);
            }

            return $namespace !== null ? $namespace . '\\' . $name : $name;
        }
        $lower = strtolower($name);
        if (isset($uses[$lower])) {
            return $uses[$lower];
        }

        return $namespace !== null ? $namespace . '\\' . $name : $name;
    }

    private function decisionIssue(
        MassAssignmentDecision $decision,
        string $method,
        string $file,
        int $line
    ): Issue {
        $model = $decision->model ?? 'unknown model';
        $protection = $this->protectionPhrase($decision);
        $metadata = [
            'method' => $method,
            'model' => $decision->model,
            'mass_assignment' => $this->payload($decision, $method),
        ];
        if ($decision->verdict === MassAssignmentDecision::EXPOSED) {
            return new Issue(
                self::RULE,
                sprintf(
                    'Mass assignment exposure: %s reaches %s::%s() with %s.',
                    $this->shortSource($decision),
                    $model,
                    strtolower($method),
                    $protection
                ),
                $file,
                $line,
                Severity::Error,
                'custom',
                $metadata,
                Confidence::High
            );
        }

        return new Issue(
            self::RULE,
            sprintf(
                'Possible mass assignment: %s reaches %s::%s() with %s.',
                $this->shortSource($decision),
                $model,
                strtolower($method),
                $protection
            ),
            $file,
            $line,
            Severity::Warning,
            'custom',
            $metadata,
            Confidence::Medium
        );
    }

    private function shortSource(MassAssignmentDecision $decision): string
    {
        foreach ($decision->trace as $step) {
            if ($step['kind'] === 'source') {
                return $step['detail'];
            }
        }

        return $decision->input;
    }

    private function protectionPhrase(MassAssignmentDecision $decision): string
    {
        foreach ($decision->evidence as $step) {
            if (str_contains($step, 'force-bypass')) {
                return 'a guard-bypassing sink ($fillable/$guarded are ignored)';
            }
            if (str_contains($step, 'globally unguarded')) {
                return 'globally disabled mass assignment protection';
            }
        }
        if ($decision->assignability === ModelMetadata::UNGUARDED) {
            return 'an unguarded model ($guarded = [])';
        }
        if ($decision->assignability === ModelMetadata::GUARDED_LIST) {
            return 'a partially guarded model';
        }

        return 'unresolved model protection';
    }

    /**
     * @return array{verdict: string, input_kind: string, source: string, sink: array{type: string, model: string|null}, model_protection: array{type: string, fields: list<string>|null}, bypass: bool, confidence: string, flow: list<array{kind: string, detail: string, line: int|null}>}
     */
    private function payload(MassAssignmentDecision $decision, string $method): array
    {
        $bypass = false;
        foreach ($decision->evidence as $step) {
            if (str_contains($step, 'force-bypass')) {
                $bypass = true;
                break;
            }
        }

        return [
            'verdict' => $decision->verdict,
            'input_kind' => $decision->input,
            'source' => $this->shortSource($decision),
            'sink' => ['type' => strtolower($method), 'model' => $decision->model],
            'model_protection' => [
                'type' => $this->protectionType($decision->assignability),
                'fields' => $decision->protectionFields,
            ],
            'bypass' => $bypass,
            'confidence' => $decision->verdict === MassAssignmentDecision::EXPOSED ? 'high' : 'medium',
            'flow' => $decision->trace,
        ];
    }

    private function protectionType(string $assignability): string
    {
        return match ($assignability) {
            ModelMetadata::FILLABLE => 'fillable',
            ModelMetadata::GUARDED_ALL => 'guarded',
            ModelMetadata::GUARDED_LIST => 'guarded',
            ModelMetadata::UNGUARDED => 'unguarded',
            default => 'unknown',
        };
    }

    /**
     * Shadow-mode flow provenance: classifies the tainting argument
     * without changing any decision. Null outside class methods.
     *
     * @param list<Node> $ast
     * @param array<int, Node\Stmt\ClassMethod|Node\Stmt\Function_> $funcs
     * @return array{status: string, fields: list<string>|null, excluded: list<string>|null, force_bypass: bool, source: string, sink: string, trace: list<array{kind: string, detail: string, line: int|null}>}|null
     */
    private function flowProvenance(
        Node\Expr\StaticCall|Node\Expr\MethodCall $call,
        Node\Expr $arg,
        string $method,
        array $ast,
        array $funcs,
        ScopeResolver $scopes,
        string $file
    ): ?array {
        $funcId = ScopeIds::outermost($call);
        $func = $funcs[$funcId] ?? null;
        if (!$func instanceof Node\Stmt\ClassMethod) {
            return null;
        }

        return MassAssignmentFlow::classify($arg, $method, $func, $ast, $funcId, $file, $call->getStartLine())->toArray();
    }

    /**
     * The argument the finding was raised for: the first argument, or —
     * for lookup/value sinks — the first tainted later argument.
     *
     * @param list<Node\Arg|Node\VariadicPlaceholder> $args
     */
    private function taintingArg(Node\Expr\StaticCall|Node\Expr\MethodCall $call, array $args, string $method): Node\Expr
    {
        $first = $args[0] ?? null;
        $firstExpr = $first instanceof Node\Arg ? $first->value : null;
        if (
            $firstExpr === null
            || $this->isRequestInput($firstExpr)
            || !in_array($method, ['updateOrCreate', 'firstOrCreate', 'updateOrInsert', 'firstOrNew'], true)
        ) {
            return $firstExpr ?? $call;
        }
        foreach (array_slice($args, 1) as $extra) {
            if ($extra instanceof Node\Arg && $this->isRequestInput($extra->value)) {
                return $extra->value;
            }
        }

        return $firstExpr;
    }

    /**
     * @param list<Node> $ast
     * @return array<string, string> alias => FQCN
     */
    private function useMap(string $file, array $ast): array
    {
        $map = [];
        /** @var list<Node\Stmt\Use_> $uses */
        $uses = $this->facts()->uses($file, $ast);
        foreach ($uses as $use) {
            foreach ($use->uses as $useUse) {
                $alias = $useUse->alias !== null
                    ? $useUse->alias->toString()
                    : $useUse->name->getLast();
                $map[strtolower($alias)] = $useUse->name->toString();
            }
        }

        return $map;
    }

    /**
     * @param list<Node> $ast
     */
    private function namespaceOf(string $file, array $ast): ?string
    {
        $found = $this->facts()->namespaces($file, $ast);
        foreach ($found as $node) {
            if ($node instanceof Node\Stmt\Namespace_ && $node->name instanceof Node\Name) {
                return $node->name->toString();
            }
        }

        return null;
    }

    private function resolveModelTarget(Node $call): ?string
    {
        if ($call instanceof Node\Expr\StaticCall && $call->class instanceof Node\Name) {
            return $call->class->toString();
        }

        return null;
    }

    /**
     * Model::unguard() (or User::unguard() on a known Eloquent model)
     * disables mass-assignment protection globally. Resolves the called
     * class through use-statements against the scanned model files, so a
     * short name like User still matches app/Models/User.php.
     *
     * @param list<Node> $ast
     * @param array<string, string> $modelClassFiles
     */
    private function isUnguardedModel(Node\Expr\StaticCall $call, string $file, array $ast, array $modelClassFiles): bool
    {
        if (!$call->class instanceof Node\Name) {
            return false;
        }
        $class = ltrim($call->class->toString(), '\\');

        if ($class === 'Model' || str_ends_with($class, '\\Model')) {
            return true;
        }

        if (isset($modelClassFiles[$class])) {
            return true;
        }

        /** @var list<Node\Stmt\Use_> $uses */
        $uses = $this->facts()->uses($file, $ast);
        foreach ($uses as $use) {
            foreach ($use->uses as $useUse) {
                $alias = $useUse->alias !== null
                    ? $useUse->alias->toString()
                    : $useUse->name->getLast();
                if ($alias === $class && isset($modelClassFiles[$useUse->name->toString()])) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Seed-data paths carry no request input by construction, so a global
     * unguard() there only affects literal seed data.
     */
    private function isSeedDataPath(string $file): bool
    {
        $normalized = strtolower(str_replace('\\', '/', $file));

        return str_contains($normalized, '/database/seeders/')
            || str_contains($normalized, '/database/factories/')
            || str_contains($normalized, '/database/migrations/')
            || str_contains($normalized, '/tests/')
            || str_starts_with($normalized, 'tests/');
    }

    /**
     * @param array<string, string> $modelClassFiles
     */
    private function modelExists(string $model, array $modelClassFiles): bool
    {
        return isset($modelClassFiles[$model]);
    }

    /**
     * @param array<string, string> $modelClassFiles
     */
    private function modelDefinesMassAssignmentGuard(string $model, array $modelClassFiles): bool
    {
        if (!isset($modelClassFiles[$model])) {
            return false;
        }

        $modelFile = $modelClassFiles[$model];
        $ast = $this->sharedAst($modelFile);
        if ($ast === null) {
            return false;
        }

        $properties = $this->facts()->properties($modelFile, $ast);

        foreach ($properties as $property) {
            if (!$property->isProtected() && !$property->isPublic()) {
                continue;
            }
            foreach ($property->props as $prop) {
                if ($prop->name instanceof Node\Identifier) {
                    $name = $prop->name->toString();
                    if ($name === 'fillable') {
                        return true;
                    }
                    // An explicitly empty $guarded = [] guards nothing —
                    // every attribute stays mass-assignable.
                    if ($name === 'guarded' && !$this->isEmptyArray($prop->default)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    private function isEmptyArray(?Node\Expr $expr): bool
    {
        return $expr instanceof Node\Expr\Array_ && $expr->items === [];
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
            $inModelDir = false;
            foreach ($this->modelDirSegments as $seg) {
                if (stripos($pathname, '/' . $seg . '/') !== false) {
                    $inModelDir = true;
                    break;
                }
            }
            if (!$inModelDir) {
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
     * @return array{string|null, string|null} [FQCN, short name]; both null when unresolvable
     */
    private function resolveClassName(string $path): array
    {
        $ast = $this->sharedAst($path);
        if ($ast === null) {
            return [null, null];
        }

        $finder = new CountingNodeFinder();
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
}
