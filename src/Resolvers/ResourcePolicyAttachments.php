<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Resolvers;

use Illuminate\Contracts\Database\Query\Builder;
use Illuminate\Database\Eloquent\Builder as EloquentBuilder;
use Illuminate\Database\Query\Builder as QueryBuilder;
use SineMacula\Laravel\Authorization\Config\TableNames;
use SineMacula\Laravel\Authorization\Database\GrantApplications;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\TenantColumns;

/**
 * The queries `ResourcePolicyResolver` reads resource policy attachments with:
 * those that hold in the tenant and application a check is decided in, and,
 * through queries united with them, those whose denies count in every scope
 * (N130, see `Support\TenantColumns`): an attachment naming half a tenant, and
 * any attachment of a policy naming half a tenant. Each added query is a range
 * of an index, the attachments' or the policies' tenant index for a key with no
 * type, their `tenant_id` index for a type with no key, so the scope's own
 * query keeps its plan and, with no such row, the added work is empty index
 * ranges.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ResourcePolicyAttachments
{
    /** @var string The column a query reads the attached resource's key into. */
    public const string RESOURCE_ID = 'attached_resource_id';

    /** @var string The column a query reads the attachment's tenant type into. */
    public const string TENANT_TYPE = 'attached_tenant_type';

    /** @var string The column a query reads the attachment's tenant key into. */
    public const string TENANT_ID = 'attached_tenant_id';

    /** @var string The column of a row holding its tenant's type. */
    private const string TYPE_COLUMN = 'tenant_type';

    /** @var string The column of a row holding its tenant's key. */
    private const string ID_COLUMN = 'tenant_id';

    /** @var string The column of an attachment holding the attached policy's key. */
    private const string POLICY_KEY = '.policy_id';

    /** @var string The name the united queries of keys are read under, as a derived table. */
    private const string KEYS = 'authz_keys';

    /** @var string The column of the derived table holding a policy's key. */
    private const string KEY = self::KEYS . self::POLICY_KEY;

    /**
     * Return a query of the policies attached to the resources of the type the
     * given callback limits the attachments to, each with what it is attached
     * to (`RESOURCE_ID`) and the attachment's tenant columns (`TENANT_TYPE`,
     * `TENANT_ID`), on the write connection: those attached in the tenant and
     * application the check is decided in, and, through queries united with it,
     * those whose denies count in every scope.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $model
     * @param  string  $type
     * @param  \Closure(\Illuminate\Contracts\Database\Query\Builder): void  $resources
     * @return \Illuminate\Database\Eloquent\Builder<\SineMacula\Laravel\Authorization\Models\Policy>
     */
    public static function of(Policy $model, string $type, \Closure $resources): EloquentBuilder
    {
        $table       = TableNames::get('resource_policies');
        $application = TenantScope::currentApplication();
        $read        = static fn (): EloquentBuilder => $model->newQuery()->withoutGlobalScopes()
            ->join($table, $table . self::POLICY_KEY, '=', $model->getQualifiedKeyName())
            ->where($table . '.resource_type', $type)
            ->where($resources)
            ->where(static fn (Builder $query): Builder => GrantApplications::only($query, $table, $application))
            ->select([
                $model->qualifyColumn('*'),
                $table . '.resource_id as ' . self::RESOURCE_ID,
                $table . '.' . self::TYPE_COLUMN . ' as ' . self::TENANT_TYPE,
                $table . '.' . self::ID_COLUMN . ' as ' . self::TENANT_ID,
            ]);

        $query = $read()->useWritePdo()->where(static fn (Builder $query): Builder => TenantScope::currentChain()->grants($query, $table));

        TenantColumns::unionHalf($query, $read, $table . '.' . self::TYPE_COLUMN, $table . '.' . self::ID_COLUMN);

        return TenantColumns::unionHalf($query, $read, $model->qualifyColumn(self::TYPE_COLUMN), $model->qualifyColumn(self::ID_COLUMN));
    }

    /**
     * Return a query of the keys of the policies attached to records of the
     * type in the tenant and application the check is decided in, and of those
     * whose denies count on them in every scope, read as a derived table, so
     * every database reads the union once rather than for each policy.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $model
     * @param  string  $type
     * @return \Illuminate\Database\Query\Builder
     */
    public static function onRecords(Policy $model, string $type): QueryBuilder
    {
        $table    = TableNames::get('resource_policies');
        $records  = self::recordRows($model, $type);
        $owned    = static fn (): QueryBuilder => $records()->join($model->getTable(), $model->getQualifiedKeyName(), '=', $table . self::POLICY_KEY);
        $attached = TenantColumns::unionHalf(TenantScope::currentChain()->grants($records(), $table), $records, $table . '.' . self::TYPE_COLUMN, $table . '.' . self::ID_COLUMN);

        return self::keysOf($model, TenantColumns::unionHalf($attached, $owned, $model->qualifyColumn(self::TYPE_COLUMN), $model->qualifyColumn(self::ID_COLUMN)));
    }

    /**
     * Return a query of the keys of the policies attached to records of the
     * type, in the check's application, by a row naming half a tenant, whose
     * denies count on those records in every scope (see
     * `TenantColumns::halves()`), read as a derived table under `KEYS`, whose
     * `policy_id` a caller can compare with the policy it reads.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $model
     * @param  string  $type
     * @return \Illuminate\Database\Query\Builder
     */
    public static function halfOnRecords(Policy $model, string $type): QueryBuilder
    {
        $table = TableNames::get('resource_policies');

        return self::keysOf($model, TenantColumns::halves(self::recordRows($model, $type), $table . '.' . self::TYPE_COLUMN, $table . '.' . self::ID_COLUMN))
            ->whereColumn(self::KEY, $model->getQualifiedKeyName());
    }

    /**
     * Return a query of the policy keys the united queries of attachments read,
     * from them as a derived table: a database that cannot read a union as a
     * semi-join, as MySQL cannot, then reads it once.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $model
     * @param  \Illuminate\Database\Query\Builder  $union
     * @return \Illuminate\Database\Query\Builder
     */
    private static function keysOf(Policy $model, QueryBuilder $union): QueryBuilder
    {
        return $model->getConnection()->query()->select(self::KEY)->fromSub($union, self::KEYS);
    }

    /**
     * Return a callback building a query of the keys of the policies attached
     * to records of the type in the check's application, in any tenant.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $model
     * @param  string  $type
     * @return \Closure(): \Illuminate\Database\Query\Builder
     */
    private static function recordRows(Policy $model, string $type): \Closure
    {
        $table       = TableNames::get('resource_policies');
        $application = TenantScope::currentApplication();

        return static function () use ($model, $table, $type, $application): QueryBuilder {
            $query = $model->getConnection()->query()->select($table . self::POLICY_KEY)->from($table)
                ->where($table . '.resource_type', $type)
                ->whereNotNull($table . '.resource_id');

            return GrantApplications::only($query, $table, $application);
        };
    }
}
