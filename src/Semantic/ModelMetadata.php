<?php

declare(strict_types=1);

namespace Rampart\QualityChecker\Semantic;

use PhpParser\Node;
use Rampart\QualityChecker\Analysis\CountingNodeFinder;
use Rampart\QualityChecker\Scanning\ScanContext;

/**
 * Eloquent model mass-assignment state. Returns state, never bare
 * arrays — `unknown` must never degrade into `empty`.
 *
 * Laravel semantics modeled exactly:
 * - `$fillable = [...]` non-empty wins over everything (FILLABLE).
 * - `$guarded = []` guards nothing (UNGUARDED).
 * - `$guarded = ['*']`, or neither property declared (framework
 *   default), guards everything (GUARDED).
 * - `$guarded = ['is_admin']` guards the listed fields (GUARDED_LIST).
 * - Dynamic values, explicit `null`, or unreadable files are UNKNOWN.
 * - A global `Model::unguard()` (outside seed paths, without reguard)
 *   marks every model unguarded; `unguarded(callback)` is scoped and
 *   does not flip global state.
 */
final class ModelMetadata
{
    public const KNOWN = 'known';

    public const UNKNOWN = 'unknown';

    public const FILLABLE = 'fillable';

    public const GUARDED_ALL = 'guarded-all';

    public const GUARDED_LIST = 'guarded-list';

    public const UNGUARDED = 'unguarded';

    public const ASSIGN_UNKNOWN = 'unknown';

    /**
     * @param list<string>|null $fillableFields null unless KNOWN non-empty
     * @param list<string>|null $guardedFields null unless KNOWN
     */
    public function __construct(
        public readonly string $model,
        public readonly string $fillableState,
        public readonly ?array $fillableFields,
        public readonly string $guardedState,
        public readonly ?array $guardedFields,
        public readonly bool $guardedAbsent,
        public readonly string $file,
    ) {
    }

    public static function unknown(string $model, string $file = ''): self
    {
        return new self($model, self::UNKNOWN, null, self::UNKNOWN, null, false, $file);
    }

    /**
     * @return array{model: string, fillable_state: string, fillable_fields: list<string>|null, guarded_state: string, guarded_fields: list<string>|null, assignability: string, assignable_fields: list<string>|null, file: string}
     */
    public function toArray(): array
    {
        [$assignability, $assignable] = $this->assignability();

        return [
            'model' => $this->model,
            'fillable_state' => $this->fillableState,
            'fillable_fields' => $this->fillableFields,
            'guarded_state' => $this->guardedState,
            'guarded_fields' => $this->guardedFields,
            'assignability' => $assignability,
            'assignable_fields' => $assignable,
            'file' => $this->file,
        ];
    }

    /**
     * @return array{string, list<string>|null} assignability + fields
     *   (null fields = open set, except GUARDED_ALL which is empty)
     */
    public function assignability(): array
    {
        if ($this->fillableState === self::KNOWN && $this->fillableFields !== null && $this->fillableFields !== []) {
            return [self::FILLABLE, $this->fillableFields];
        }
        if ($this->fillableState === self::UNKNOWN) {
            return [self::ASSIGN_UNKNOWN, null];
        }
        if ($this->guardedState === self::KNOWN && $this->guardedFields !== null) {
            if ($this->guardedFields === []) {
                return [self::UNGUARDED, null];
            }
            if ($this->guardedFields === ['*']) {
                return [self::GUARDED_ALL, []];
            }

            return [self::GUARDED_LIST, null];
        }
        if ($this->guardedState === self::UNKNOWN) {
            return [self::ASSIGN_UNKNOWN, null];
        }
        // No guarded declaration at all: framework default ['*'].
        if ($this->guardedAbsent) {
            return [self::GUARDED_ALL, []];
        }

        return [self::ASSIGN_UNKNOWN, null];
    }

    public static function fromFile(string $model, string $file, ?ScanContext $scan = null): self
    {
        $scan ??= new ScanContext();
        $code = $scan->source($file);
        if ($code === '') {
            return self::unknown($model, $file);
        }
        $ast = $scan->ast($file);
        if ($ast === null) {
            return self::unknown($model, $file);
        }
        $finder = new CountingNodeFinder();
        $classes = $finder->findInstanceOf($ast, Node\Stmt\Class_::class);
        foreach ($classes as $class) {
            if (!$class instanceof Node\Stmt\Class_) {
                continue;
            }
            $fillable = self::stringListProp($class, 'fillable');
            $guarded = self::stringListProp($class, 'guarded');

            return new self(
                $model,
                $fillable['state'],
                $fillable['fields'],
                $guarded['state'],
                $guarded['fields'],
                $guarded['absent'],
                $file
            );
        }

        return self::unknown($model, $file);
    }

    /**
     * @return array{state: string, fields: list<string>|null, absent: bool}
     */
    private static function stringListProp(Node\Stmt\Class_ $class, string $name): array
    {
        foreach ($class->stmts as $stmt) {
            if (!$stmt instanceof Node\Stmt\Property) {
                continue;
            }
            foreach ($stmt->props as $prop) {
                if (!$prop->name instanceof Node\Identifier || $prop->name->toString() !== $name) {
                    continue;
                }
                if (!$prop->default instanceof Node\Expr\Array_) {
                    // Dynamic value or explicit null: unknown, and the
                    // property is present (not absent).
                    return ['state' => self::UNKNOWN, 'fields' => null, 'absent' => false];
                }
                $fields = [];
                foreach ($prop->default->items as $item) {
                    if (!$item instanceof Node\Expr\ArrayItem || !$item->value instanceof Node\Scalar\String_) {
                        return ['state' => self::UNKNOWN, 'fields' => null, 'absent' => false];
                    }
                    $fields[] = $item->value->value;
                }

                return ['state' => self::KNOWN, 'fields' => $fields, 'absent' => false];
            }
        }

        return ['state' => self::KNOWN, 'fields' => null, 'absent' => true];
    }
}
