<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Query;

use Illuminate\Database\Connection;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableResource;
use SineMacula\Laravel\Authorization\Contracts\QueryableResource;
use SineMacula\Laravel\Authorization\Exceptions\QueryScopeRefusedException;
use SineMacula\Laravel\Authorization\Query\Contracts\Dialect;
use SineMacula\Laravel\Authorization\Query\Dialects\Dialects;
use SineMacula\Laravel\Authorization\Query\Enums\ColumnKind;
use SineMacula\Laravel\Authorization\Query\Enums\RefusalReason;
use SineMacula\Laravel\Authorization\Support\ResourceTenancy;

/**
 * What an authorized scope knows of the model it scopes, checked before
 * anything is compiled (AUTHZ-10.1, N68): its morph type, its table and
 * connection, the dialect it is written in, its key and its tenant columns,
 * wrapped and qualified, and their kinds, and whether its key can be compared
 * with a value exactly: an integer key holds only integers PHP reads as they
 * are, and a string key's collation compares bytes.
 *
 * A model is refused, at once, when the scope cannot prove that what the
 * database compares is what `check()` reads from a loaded record: it does not
 * declare its tenancy (`QueryableResource`); it names its own resource
 * (`AuthorizableResource`); it overrides a method that could change what a
 * loaded record reads as, or has a `retrieved` listener that could change the
 * record once loaded; its key or a tenant column has an accessor, or a cast
 * other than the key's own (an integer key's integer cast, a string key's
 * string cast); a column is missing or of a kind the dialect cannot compare;
 * its connection is not SQLite, PostgreSQL or MySQL, or not UTF-8; or its morph
 * type is so long that no record's identifier could be matched.
 *
 * A model's own `$dispatchesEvents` is read through reflection, since a model
 * keeps it protected (hence php:S3011).
 *
 * @SuppressWarnings("php:S3011")
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ResourceShape
{
    /** @var list<string> The methods a model may not override, since each could change what a loaded record reads as. */
    public const array SEALED = ['getMorphClass', 'newFromBuilder', 'getKey', 'getKeyName', 'getAttribute', 'getAttributes', 'getAttributeValue', 'setRawAttributes'];

    /** @var int The most bytes the text of a bounded key holds: a uuid's 36, an integer's 20, with room. */
    private const int BOUNDED_KEY_BYTES = 64;

    /**
     * Create a new resource shape.
     *
     * @param  string  $type
     * @param  string  $table
     * @param  \SineMacula\Laravel\Authorization\Query\Contracts\Dialect  $dialect
     * @param  string  $key
     * @param  \SineMacula\Laravel\Authorization\Query\Enums\ColumnKind  $keyKind
     * @param  bool  $isIntegerCast
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceTenancy  $tenancy
     * @param  string|null  $typeColumn
     * @param  string|null  $idColumn
     * @param  \SineMacula\Laravel\Authorization\Query\Enums\ColumnKind|null  $idKind
     * @param  \Illuminate\Database\Connection|null  $connection
     * @param  string  $keyName
     * @param  \SineMacula\Laravel\Authorization\Query\Enums\RefusalReason|null  $keyRefusal
     * @param  bool  $isKeyCollationExact
     */
    private function __construct(

        /** The model's morph type. */
        public string $type,

        /** The model's table, as the query selects from it. */
        public string $table,

        /** The dialect of the model's connection. */
        public Dialect $dialect,

        /** The key column, qualified and wrapped. */
        public string $key,

        /** The key column's kind. */
        public ColumnKind $keyKind,

        /** Whether the model casts its key to an integer. */
        public bool $isIntegerCast,

        /** Where the model's records keep their tenant. */
        public ResourceTenancy $tenancy,

        /** The tenant type column, qualified and wrapped, or null when there is none. */
        public ?string $typeColumn,

        /** The tenant id column, qualified and wrapped, or null for a tenantless model. */
        public ?string $idColumn,

        /** The tenant id column's kind, or null for a tenantless model. */
        public ?ColumnKind $idKind = null,

        /** The model's connection, or null when it is not known. */
        public ?Connection $connection = null,

        /** The key column's bare name, which refusals name. */
        public string $keyName = '',

        /** Why the key cannot be compared with a value at all (an integer key that may hold what PHP reads otherwise), or null when it can. */
        public ?RefusalReason $keyRefusal = null,

        /** Whether the key column's collation compares bytes, so a comparison with its text is exact under it too. */
        public bool $isKeyCollationExact = true,
    ) {}

    /**
     * Return the shape of the model, refusing a model the scope cannot compile
     * exactly; every refusal names the model's morph type.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  string  $action
     * @param  \SineMacula\Laravel\Authorization\Query\SchemaInspector  $inspector
     * @return self
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\QueryScopeRefusedException
     */
    public static function of(Model $model, string $action, SchemaInspector $inspector): self
    {
        $type   = $model->getMorphClass();
        $refuse = static function (RefusalReason $reason, ?string $key = null, ?string $detail = null) use ($type, $action): never {
            throw QueryScopeRefusedException::of($action, $type, new Refusal($reason, null, null, $key, $detail));
        };

        if (!$model instanceof QueryableResource) {
            $refuse(RefusalReason::MODEL_UNDECLARED, $model::class);
        }

        $hook = self::hookOf($model);

        if ($hook !== null) {
            $refuse(...$hook);
        }

        $connection = $model->getConnection();
        $dialect    = Dialects::for($connection->getDriverName()) ?? $refuse(RefusalReason::DRIVER, $connection->getDriverName());

        if (!$inspector->isUtf8($connection, $dialect)) {
            $refuse(RefusalReason::CONNECTION_CHARSET, (string) $connection->getName());
        }

        $tenancy = $model::resourceTenancy();
        $kinds   = self::kindsOf($model, $connection, $dialect, $inspector, $tenancy, $refuse);
        $wrap    = static fn (?string $column): ?string => $column === null ? null : $connection->getQueryGrammar()->wrap($model->qualifyColumn($column));

        if (\strlen($type) + 1 + self::BOUNDED_KEY_BYTES >= \PHP_MAXPATHLEN) {
            $refuse(RefusalReason::MODEL_CONTRACT, null, 'the morph type is too long to identify a record');
        }

        /** @var string $key */
        $key = $wrap($model->getKeyName());

        $idKind  = $tenancy->isTenantless() ? null : $kinds[\count($kinds) - 1];
        $table   = $model->getTable();
        $keyName = $model->getKeyName();
        $columns = [$wrap($tenancy->typeColumn), $wrap($tenancy->idColumn), $idKind, $connection, $keyName];

        // Whether the key can be compared with a value is asked only when a
        // comparison is material, so it is kept rather than refused here.
        $keyRefusal  = $kinds[0] === ColumnKind::INTEGER && !$inspector->isExactInteger($connection, $dialect, $table, $keyName) ? RefusalReason::COLUMN_TYPE : null;
        $isCollation = $kinds[0] !== ColumnKind::STRING || $inspector->isExactCollation($connection, $dialect, $table, $keyName);

        return new self($type, $table, $dialect, $key, $kinds[0], self::isIntegerCast($model), $tenancy, ...[...$columns, $keyRefusal, $isCollation]);
    }

    /**
     * Return why a model's loaded records could read otherwise than the
     * database holds them, with what it names: it names its own resource,
     * overrides a sealed method, or has a `retrieved` listener; or null when
     * none of these holds.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return array{\SineMacula\Laravel\Authorization\Query\Enums\RefusalReason, string}|null
     */
    private static function hookOf(Model $model): ?array
    {
        $isOverridden = static fn (string $method): bool => (new \ReflectionMethod($model, $method))->getDeclaringClass()->getName() !== Model::class;
        $overridden   = \array_values(\array_filter(self::SEALED, $isOverridden));

        // A model may dispatch its own event class on retrieval, which a
        // listener of that class hears instead.
        $events     = (new \ReflectionProperty($model, 'dispatchesEvents'))->getValue($model);
        $isListened = (\is_array($events) && isset($events['retrieved'])) || $model::getEventDispatcher()?->hasListeners('eloquent.retrieved: ' . $model::class) === true;

        return match (true) {
            $model instanceof AuthorizableResource => [RefusalReason::MODEL_CONTRACT, AuthorizableResource::class],
            $overridden !== []                     => [RefusalReason::MODEL_OVERRIDE, $overridden[0]],
            $isListened                            => [RefusalReason::MODEL_LISTENER, 'retrieved'],
            default                                => null,
        };
    }

    /**
     * Return the kinds of the key column and the tenant columns, in that order,
     * refusing a column that cannot be compared exactly.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  \Illuminate\Database\Connection  $connection
     * @param  \SineMacula\Laravel\Authorization\Query\Contracts\Dialect  $dialect
     * @param  \SineMacula\Laravel\Authorization\Query\SchemaInspector  $inspector
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceTenancy  $tenancy
     * @param  \Closure(\SineMacula\Laravel\Authorization\Query\Enums\RefusalReason, string|null=, string|null=): never  $refuse
     * @return non-empty-list<\SineMacula\Laravel\Authorization\Query\Enums\ColumnKind>
     */
    private static function kindsOf(Model $model, Connection $connection, Dialect $dialect, SchemaInspector $inspector, ResourceTenancy $tenancy, \Closure $refuse): array
    {
        $columns = $inspector->columns($connection, $model->getTable());
        $kinds   = [];

        foreach ([$model->getKeyName(), ...$tenancy->columnNames()] as $index => $name) {
            $kind   = isset($columns[$name]) ? $dialect->kindOf($columns[$name]) : null;
            $reason = self::columnRefusalOf($model, $name, $kind, $index === 0, $tenancy);

            if ($reason !== null || $kind === null) {
                $refuse($reason ?? RefusalReason::COLUMN_TYPE, $name);
            }

            $kinds[] = $kind;
        }

        return $kinds;
    }

    /**
     * Return why a column cannot be compared exactly, or null when it can: it
     * is missing or of a kind the dialect cannot compare, a tenant type column
     * that is not a string, or read through an accessor or a cast.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  string  $name
     * @param  \SineMacula\Laravel\Authorization\Query\Enums\ColumnKind|null  $kind
     * @param  bool  $isKey
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceTenancy  $tenancy
     * @return \SineMacula\Laravel\Authorization\Query\Enums\RefusalReason|null
     */
    private static function columnRefusalOf(Model $model, string $name, ?ColumnKind $kind, bool $isKey, ResourceTenancy $tenancy): ?RefusalReason
    {
        return match (true) {
            $kind === null               || ($name === $tenancy->typeColumn && $kind !== ColumnKind::STRING) => RefusalReason::COLUMN_TYPE,
            $model->hasGetMutator($name) || $model->hasAttributeGetMutator($name)                            => RefusalReason::COLUMN_ACCESSOR,
            !self::isRawCast($model, $name, $isKey ? $kind : null)                                           => RefusalReason::COLUMN_CAST,
            default                                                                                          => null,
        };
    }

    /**
     * Determine whether a column's cast leaves it as `check()` compares it:
     * none at all, or, for the key, its own kind's (an integer key's integer
     * cast, a string or uuid key's string cast).
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  string  $column
     * @param  \SineMacula\Laravel\Authorization\Query\Enums\ColumnKind|null  $keyKind
     * @return bool
     */
    private static function isRawCast(Model $model, string $column, ?ColumnKind $keyKind): bool
    {
        $cast = $model->getCasts()[$column] ?? null;

        if ($cast === null) {
            return true;
        }

        $cast = \strtolower($cast);

        return $keyKind === ColumnKind::INTEGER ? \in_array($cast, ['int', 'integer'], true) : $keyKind !== null && $cast === 'string';
    }

    /**
     * Determine whether the model casts its key to an integer.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return bool
     */
    private static function isIntegerCast(Model $model): bool
    {
        return \in_array(\strtolower($model->getCasts()[$model->getKeyName()] ?? ''), ['int', 'integer'], true);
    }
}
