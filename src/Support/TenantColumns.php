<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use Illuminate\Contracts\Database\Query\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Query\Builder as QueryBuilder;
use SineMacula\Laravel\Authorization\Config\TableNames;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;

/**
 * The pair of tenant columns a stored row holds, read the way the package fails
 * closed on a row naming half a tenant, a type without a key or a key without a
 * type, which the package never writes (N130).
 *
 * Such a row is neither the platform's nor any tenant's. A row of it that
 * grants (a role, permission or policy grant, a role's policy attachment, a
 * resource policy's allows, the ownership of a role or a permission) applies
 * nowhere, as `TenantChain` reads it. A row of it that restricts (a boundary, a
 * guardrail, and the denies of a policy attachment or a resource policy)
 * applies everywhere: at the platform, in every tenant and below every tenant,
 * as a platform row does. An attachment of a policy naming half a tenant is
 * read the same way, in every scope, its denies alone counting, whatever scope
 * the attachment names. A review lists either kind as `malformed`.
 *
 * A reader of one grantee's or one record's rows, through their own index,
 * filters such rows among them (`restricting()`, `attachments()`); a reader of
 * a whole table reads them through queries of their own united with its own,
 * each half a range of an index (`unionHalf()`, `halves()`), so its own plan is
 * kept, and with no such row the added work is two empty index ranges.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class TenantColumns
{
    /** @var string The column a row names its tenant's type in. */
    private const string TYPE = 'tenant_type';

    /** @var string The column a row names its tenant's key in. */
    private const string ID = 'tenant_id';

    /** @var string The name the policies table is read under, for the policy an attachment attaches. */
    private const string OWNER = 'authz_half_owner';

    /**
     * Determine whether the tenant columns name half a tenant: one of them is
     * null and the other is not.
     *
     * @param  mixed  $type
     * @param  mixed  $id
     * @return bool
     */
    public static function isHalf(mixed $type, mixed $id): bool
    {
        return ($type === null) !== ($id === null);
    }

    /**
     * Determine whether an attachment of a policy counts for its denies alone:
     * the attachment, or the policy it attaches, names half a tenant.
     *
     * @param  mixed  $type
     * @param  mixed  $id
     * @param  \Illuminate\Database\Eloquent\Model|null  $policy
     * @return bool
     */
    public static function isDenyOnly(mixed $type, mixed $id, ?Model $policy = null): bool
    {
        return self::isHalf($type, $id) || ($policy !== null && self::isHalf($policy->getAttribute(self::TYPE), $policy->getAttribute(self::ID)));
    }

    /**
     * Limit the query to the rows naming half a tenant, or add them, given the
     * boolean `or`.
     *
     * @template TQuery of \Illuminate\Contracts\Database\Query\Builder
     *
     * @param  TQuery  $query
     * @param  string  $typeColumn
     * @param  string  $idColumn
     * @param  string  $boolean
     * @return TQuery
     */
    public static function whereHalf(Builder $query, string $typeColumn, string $idColumn, string $boolean = 'and'): Builder
    {
        $query->where(static function (Builder $half) use ($typeColumn, $idColumn): void {
            $half->where(static fn (Builder $row): Builder => $row->whereNull($typeColumn)->whereNotNull($idColumn))
                ->orWhere(static fn (Builder $row): Builder => $row->whereNotNull($typeColumn)->whereNull($idColumn));
        }, null, null, $boolean);

        return $query;
    }

    /**
     * Limit a query of what restricts, a boundary or a record's attachments, to
     * the rows that hold in the chain's tenant (see `TenantChain::grants()`)
     * and those naming half a tenant, which hold everywhere; only for a query
     * already limited to a grantee's or a record's rows through an index.
     *
     * @template TQuery of \Illuminate\Contracts\Database\Query\Builder
     *
     * @param  \SineMacula\Laravel\Authorization\Support\TenantChain  $chain
     * @param  TQuery  $query
     * @param  string  $table
     * @return TQuery
     */
    public static function restricting(TenantChain $chain, Builder $query, string $table): Builder
    {
        $query->where(static function (Builder $query) use ($chain, $table): void {
            $chain->grants($query, $table);
            self::whereHalf($query, $table . '.' . self::TYPE, $table . '.' . self::ID, 'or');
        });

        return $query;
    }

    /**
     * Add to a query reading a whole table, not one grantee's or one record's
     * rows, the rows naming half a tenant, as two more queries of it united
     * with it: the rows with a key and no type, then those with a type and no
     * key, each read as the given callback builds a query of the same columns.
     * Each half is a range of an index (the table's tenant index, and its
     * `tenant_id` index), so the query keeps its own plan and, with no such
     * row, finds nothing in either range.
     *
     * @template TQuery of \Illuminate\Contracts\Database\Query\Builder
     *
     * @param  TQuery  $query
     * @param  \Closure(): \Illuminate\Contracts\Database\Query\Builder  $arm
     * @param  string  $typeColumn
     * @param  string  $idColumn
     * @return TQuery
     */
    public static function unionHalf(Builder $query, \Closure $arm, string $typeColumn, string $idColumn): Builder
    {
        foreach ([[$typeColumn, $idColumn], [$idColumn, $typeColumn]] as [$missing, $named]) {
            $query->unionAll($arm()->whereNull($missing)->whereNotNull($named));
        }

        return $query;
    }

    /**
     * Return a query of the rows of a whole table naming half a tenant, as two
     * queries the given callback builds united: the rows with a key and no
     * type, then those with a type and no key, each a range of an index (see
     * `unionHalf()`).
     *
     * @template TQuery of \Illuminate\Contracts\Database\Query\Builder
     *
     * @param  \Closure(): TQuery  $arm
     * @param  string  $typeColumn
     * @param  string  $idColumn
     * @return TQuery
     */
    public static function halves(\Closure $arm, string $typeColumn, string $idColumn): Builder
    {
        $query = $arm();

        $query->whereNull($typeColumn)->whereNotNull($idColumn);
        $query->unionAll($arm()->whereNull($idColumn)->whereNotNull($typeColumn));

        return $query;
    }

    /**
     * Limit a query of policy attachments to those that hold in the chain's
     * tenant (see `TenantChain::grants()`) and those whose denies alone count
     * everywhere (see `whereDenyOnly()`); the reader tells the two apart with
     * `isDenyOnly()`. Only for a query already limited to a grantee's rows,
     * through an index, which the added rows are filtered among.
     *
     * @template TQuery of \Illuminate\Contracts\Database\Query\Builder
     *
     * @param  \SineMacula\Laravel\Authorization\Support\TenantChain  $chain
     * @param  TQuery  $query
     * @param  string  $table
     * @return TQuery
     */
    public static function attachments(TenantChain $chain, Builder $query, string $table): Builder
    {
        $query->where(static function (Builder $query) use ($chain, $table): void {
            $chain->grants($query, $table);
            self::whereDenyOnly($query, $table, 'or');
        });

        return $query;
    }

    /**
     * Limit a query of policy attachments to those whose denies alone count, in
     * every scope: an attachment naming half a tenant, and any attachment of a
     * policy naming half a tenant, the policy read by its key, row by row; or
     * add them, given the boolean `or`.
     *
     * @template TQuery of \Illuminate\Contracts\Database\Query\Builder
     *
     * @param  TQuery  $query
     * @param  string  $table
     * @param  string  $boolean
     * @return TQuery
     */
    public static function whereDenyOnly(Builder $query, string $table, string $boolean = 'and'): Builder
    {
        $query->where(static function (Builder $query) use ($table): void {
            self::whereHalf($query, $table . '.' . self::TYPE, $table . '.' . self::ID);

            $query->orWhereExists(static function (QueryBuilder $owned) use ($table): void {
                $owned->selectRaw('1')->from(TableNames::get('policies') . ' as ' . self::OWNER)->whereColumn(self::OWNER . '.id', $table . '.policy_id');

                self::whereHalf($owned, self::OWNER . '.' . self::TYPE, self::OWNER . '.' . self::ID);
            });
        }, null, null, $boolean);

        return $query;
    }

    /**
     * Describe tenant columns naming half a tenant as stored, the missing half
     * as null, so a row is never shown or reported as the platform's or a
     * tenant's.
     *
     * @param  mixed  $type
     * @param  mixed  $id
     * @return string
     */
    public static function malformed(mixed $type, mixed $id): string
    {
        return 'malformed (tenant_type=' . self::shown($type) . ', tenant_id=' . self::shown($id) . ')';
    }

    /**
     * Write to the log channel that a row naming half a tenant was removed,
     * labelled as malformed, since no event can say where it held: once the
     * package connection's transaction commits, as an event of the removal
     * would be dispatched (see `OperationScope`), so a removal rolled back is
     * never logged, or straight away when it has none open.
     *
     * @param  string  $what
     * @param  mixed  $type
     * @param  mixed  $id
     * @param  array<string, mixed>  $context
     * @return void
     */
    public static function reportRemoved(string $what, mixed $type, mixed $id, array $context = []): void
    {
        $message    = "Authorization: removed {$what} naming half a tenant, " . self::malformed($type, $id) . '.';
        $report     = static fn () => AuthorizationLog::warning($message, [...$context, self::TYPE => $type, self::ID => $id]);
        $connection = AuthorizationConnection::connection();

        $connection->transactionLevel() === 0 ? $report() : $connection->afterCommit($report);
    }

    /**
     * Return a tenant column's value as it is shown, null as `null`.
     *
     * @param  mixed  $value
     * @return string
     */
    private static function shown(mixed $value): string
    {
        return \is_scalar($value) ? (string) $value : 'null';
    }
}
