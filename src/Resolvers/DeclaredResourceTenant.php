<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Resolvers;

use Illuminate\Container\Container;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use SineMacula\Laravel\Authorization\Contracts\QueryableResource;
use SineMacula\Laravel\Authorization\Contracts\ResourceTenantResolver;
use SineMacula\Laravel\Authorization\Query\Dialects\PostgresDialect;
use SineMacula\Laravel\Authorization\Query\SchemaInspector;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceTenancy;

/**
 * The resource tenant resolver the package binds (AUTHZ-4.4, AUTHZ-10.1): a
 * model that declares its tenancy (`QueryableResource`) is answered from its
 * declaration, so `check()` reads a record's tenant from the same columns, raw,
 * as `whereAuthorized()` compares; every other model, and every pair naming
 * one, is answered by the resolver the application configures, which this one
 * wraps. No tenant is inferred for a model that declares none (N10).
 *
 * A pair names a declared model by its morph type, through the morph map, or by
 * its class: the record is looked up for its tenant columns alone, with no
 * scope, on the write connection, so a record just moved to another tenant is
 * read as it is now, not as a replica last saw it. A pair naming a record that
 * does not exist cannot be told, so the check denies it as
 * `resource_unresolved`; so does a pair whose key the key column could not
 * hold, which is never looked up: a key that is not an integer for an
 * integer-keyed model, and, on PostgreSQL, which raises an error for it (and
 * aborts the transaction around the query), a key that is not an integer the
 * column's integer type holds, not a uuid for a uuid column, or not UTF-8.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class DeclaredResourceTenant implements ResourceTenantResolver
{
    /**
     * Create a new declared resource tenant resolver.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\ResourceTenantResolver  $fallback
     */
    public function __construct(

        /** Answers every model that declares no tenancy. */
        private ResourceTenantResolver $fallback,
    ) {}

    /**
     * Return the tenant that owns the model: from its declaration when it has
     * one, else as the configured resolver answers.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $resource
     * @return \SineMacula\Laravel\Authorization\Support\Reference|null
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    #[\Override]
    public function tenantOf(Model $resource): ?Reference
    {
        return $resource instanceof QueryableResource ? $resource::resourceTenancy()->tenantOf($resource) : $this->fallback->tenantOf($resource);
    }

    /**
     * Return the tenant that owns the record a `(type, id)` pair names: for a
     * declared model, none when it is tenantless, else the looked-up record's,
     * or false when there is no such record; for any other, as the configured
     * resolver answers.
     *
     * @param  string  $type
     * @param  string  $id
     * @return false|\SineMacula\Laravel\Authorization\Support\Reference|null
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    #[\Override]
    public function tenantOfRecord(string $type, string $id): false|Reference|null
    {
        $class = self::declaredClass($type);

        if ($class === null) {
            return $this->fallback->tenantOfRecord($type, $id);
        }

        $tenancy = $class::resourceTenancy();

        return $tenancy->isTenantless() ? null : self::recordTenant(new $class, $tenancy, $id);
    }

    /**
     * Return the tenant of the declared model's record of the key, read from
     * its tenant columns on the write connection, or false when there is no
     * such record. A key the key column could not hold names no record, so it
     * is never looked up, which PostgreSQL would answer with an error.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceTenancy  $tenancy
     * @param  string  $id
     * @return false|\SineMacula\Laravel\Authorization\Support\Reference|null
     *
     * @throws \InvalidArgumentException
     * @throws \UnexpectedValueException
     */
    private static function recordTenant(Model $model, ResourceTenancy $tenancy, string $id): false|Reference|null
    {
        $isKey  = ($model->getKeyType() !== 'int' || \preg_match('/\A-?\d{1,18}\z/', $id) === 1) && self::isComparableKey($model, $id);
        $record = $isKey ? $model->newQueryWithoutScopes()->useWritePdo()->whereKey($id)->first($tenancy->columnNames()) : null;

        return $record === null ? false : $tenancy->tenantOf($record);
    }

    /**
     * Determine whether the model's key column can be compared with the key
     * without the database raising an error, which only PostgreSQL raises.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  string  $id
     * @return bool
     */
    private static function isComparableKey(Model $model, string $id): bool
    {
        $connection = $model->getConnection();

        if ($connection->getDriverName() !== 'pgsql') {
            return true;
        }

        /** @var \SineMacula\Laravel\Authorization\Query\SchemaInspector $inspector */
        $inspector = Container::getInstance()->make(SchemaInspector::class);

        return (new PostgresDialect)->isComparableKey($inspector->columns($connection, $model->getTable())[$model->getKeyName()] ?? [], $id);
    }

    /**
     * Return the declared model class a type names, through the morph map or as
     * a class, or null when it names none.
     *
     * @param  string  $type
     * @return class-string<\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authorization\Contracts\QueryableResource>|null
     */
    private static function declaredClass(string $type): ?string
    {
        $class = Relation::getMorphedModel($type) ?? $type;

        if (!\is_subclass_of($class, Model::class) || !\is_subclass_of($class, QueryableResource::class)) {
            return null;
        }

        return (new \ReflectionClass($class))->isAbstract() ? null : $class;
    }
}
