<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Reviews\Support;

use Illuminate\Database\Query\Builder;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;

/**
 * The queries an access review reads stored rows through: the rows of a grant
 * table or of the role permission edges, selected under the column names
 * `GrantRow` reads, on the package's write connection, as every grant read is
 * (AUTHZ-12.4), and ordered in the review's order (see `ReviewOrder`).
 *
 * A query is read a page at a time, never whole, so what a review holds in
 * memory is bounded by its limit, not by the rows stored.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class GrantRows
{
    /** @var list<string> The columns of a grant row read beside its target and grantee, each under its own name. */
    private const array COLUMNS = ['tenant_type', 'tenant_id', 'include_subtree', 'application', 'expires_at', 'created_at', 'updated_at', 'granted_by_type', 'granted_by_id'];

    /**
     * Return a query of the rows of the grant table of the kind, each with its
     * target's key, its grantee and every column a review reads.
     *
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $target
     * @return \Illuminate\Database\Query\Builder
     */
    public static function of(GrantTarget $target): Builder
    {
        $table   = $target->table();
        $columns = [$table . '.' . $target->column() . ' as target_id', $table . '.authorizable_type as grantee_type', $table . '.authorizable_id as grantee_id'];

        foreach (self::COLUMNS as $column) {
            $columns[] = $table . '.' . $column;
        }

        return AuthorizationConnection::connection()->table($table)->useWritePdo()->select($columns);
    }

    /**
     * Return a query of the role permission edges, each with its permission's
     * key as the target, its role's as the grantee, and its expiry.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    public static function edges(): Builder
    {
        $table = Definitions::edges();

        return AuthorizationConnection::connection()
            ->table($table)
            ->useWritePdo()
            ->select([$table . '.permission_id as target_id', $table . '.role_id as grantee_id', $table . '.expires_at']);
    }

    /**
     * Limit a grant query to the rows granted to one of the grantees, each
     * matched by its exact morph type and key.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  string  $table
     * @param  list<\SineMacula\Laravel\Authorization\Support\Reference>  $grantees
     * @return \Illuminate\Database\Query\Builder
     */
    public static function grantedTo(Builder $query, string $table, array $grantees): Builder
    {
        return $query->where(static function (Builder $any) use ($table, $grantees): void {
            if ($grantees === []) {
                $any->whereRaw('1 = 0');

                return;
            }

            foreach ($grantees as $grantee) {
                $any->orWhere(static function (Builder $pair) use ($table, $grantee): void {
                    $pair->where($table . '.authorizable_type', $grantee->type)->where($table . '.authorizable_id', $grantee->id);
                });
            }
        });
    }

    /**
     * Order a grant query in the review's order: by its target first when
     * asked, then by its grantee's type and key, its tenant's, its application
     * and its reach, then by its target when not first, so the order is total
     * over the rows a grant table can hold.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  string  $table
     * @param  string  $target
     * @param  bool  $isTargetFirst
     * @return \Illuminate\Database\Query\Builder
     */
    public static function ordered(Builder $query, string $table, string $target, bool $isTargetFirst = true): Builder
    {
        if ($isTargetFirst) {
            ReviewOrder::by($query, $table . '.' . $target);
        }

        ReviewOrder::by($query, $table . '.authorizable_type');
        ReviewOrder::by($query, $table . '.authorizable_id');
        ReviewOrder::by($query, $table . '.tenant_type', true);
        ReviewOrder::by($query, $table . '.tenant_id', true);
        ReviewOrder::by($query, $table . '.application', true);

        $query->orderBy($table . '.include_subtree');

        return $isTargetFirst ? $query : ReviewOrder::by($query, $table . '.' . $target);
    }

    /**
     * Read every row of the query as a stored row of the source.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  string  $source
     * @return list<\SineMacula\Laravel\Authorization\Reviews\Support\GrantRow>
     */
    public static function all(Builder $query, string $source): array
    {
        $rows = [];

        foreach ($query->get() as $row) {
            $rows[] = GrantRow::from($row, $source);
        }

        return $rows;
    }

    /**
     * Read a page of the query's rows as stored rows of the source, the grantee
     * of an edge being a role of the type given.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  string  $source
     * @param  int  $offset
     * @param  int  $limit
     * @param  string|null  $roleType
     * @return list<\SineMacula\Laravel\Authorization\Reviews\Support\GrantRow>
     */
    public static function page(Builder $query, string $source, int $offset, int $limit, ?string $roleType = null): array
    {
        $rows = [];

        foreach ((clone $query)->offset($offset)->limit($limit)->get() as $row) {
            $rows[] = GrantRow::from($row, $source, $roleType);
        }

        return $rows;
    }
}
