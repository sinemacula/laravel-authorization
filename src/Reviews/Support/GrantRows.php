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
 * A query of holders or of stored rows is read a page at a time, each page
 * resuming after a position in the review's order by keyset (see `after()` and
 * `Keyset`), never at an offset, so what such a review holds in memory is
 * bounded by its limit, not by the rows stored, and a page costs the same
 * whatever its number; one subject's holdings are read whole by design (see
 * `HoldingRoutes`), their grantees a chunk at a time (see `CHUNK`), so no
 * query's bindings grow with the principals an identity has.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class GrantRows
{
    /** @var int The most grantees one query of grants is limited to. */
    public const int CHUNK = 500;

    /** @var string The column of a grant row naming its grantee's type. */
    private const string GRANTEE_TYPE = '.authorizable_type';

    /** @var string The column of a grant row naming its grantee's key. */
    private const string GRANTEE_ID = '.authorizable_id';

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
        $columns = [$table . '.' . $target->column() . ' as target_id', $table . self::GRANTEE_TYPE . ' as grantee_type', $table . self::GRANTEE_ID . ' as grantee_id'];

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
     * matched by its exact morph type and key, the grantees of one type matched
     * together, so the query holds one term for each type, not each grantee.
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

            $types = [];

            foreach ($grantees as $grantee) {
                $types[ReviewOrder::key([$grantee->type])]['type']              = $grantee->type;
                $types[ReviewOrder::key([$grantee->type])]['ids'][$grantee->id] = $grantee->id;
            }

            foreach ($types as ['type' => $type, 'ids' => $ids]) {
                $any->orWhere(static function (Builder $pair) use ($table, $type, $ids): void {
                    $pair->where($table . self::GRANTEE_TYPE, $type)->whereIn($table . self::GRANTEE_ID, \array_values($ids));
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

        ReviewOrder::by($query, $table . self::GRANTEE_TYPE);
        ReviewOrder::by($query, $table . self::GRANTEE_ID);
        ReviewOrder::by($query, $table . '.tenant_type', true);
        ReviewOrder::by($query, $table . '.tenant_id', true);
        ReviewOrder::by($query, $table . '.application', true);

        $query->orderBy($table . '.include_subtree');

        return $isTargetFirst ? $query : ReviewOrder::by($query, $table . '.' . $target);
    }

    /**
     * Read every row of the grants of each chunk of the grantees, the query of
     * a chunk given by the callback limited to the chunk, as stored rows of the
     * source, in the order of the chunks, one query a chunk.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Support\Reference>  $grantees
     * @param  \Closure(list<\SineMacula\Laravel\Authorization\Support\Reference>): \Illuminate\Database\Query\Builder  $query
     * @param  string  $source
     * @return list<\SineMacula\Laravel\Authorization\Reviews\Support\GrantRow>
     */
    public static function allOf(array $grantees, \Closure $query, string $source): array
    {
        $rows = [];

        foreach (\array_chunk($grantees, self::CHUNK) as $chunk) {
            \array_push($rows, ...self::all($query($chunk), $source));
        }

        return $rows;
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
     * Read at most the limit of the query's rows, in its order, as stored rows
     * of the source, the grantee of an edge being a role of the type given; the
     * query names where to start by its keyset, never by an offset.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  string  $source
     * @param  int  $limit
     * @param  string|null  $roleType
     * @return list<\SineMacula\Laravel\Authorization\Reviews\Support\GrantRow>
     */
    public static function page(Builder $query, string $source, int $limit, ?string $roleType = null): array
    {
        $rows = [];

        foreach ($query->limit($limit)->get() as $row) {
            $rows[] = GrantRow::from($row, $source, $roleType);
        }

        return $rows;
    }

    /**
     * Limit a grant query ordered as `ordered()` orders it to the rows after
     * the position, or at it too when asked (see `Keyset`).
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  string  $table
     * @param  string  $target
     * @param  bool  $isTargetFirst
     * @param  list<bool|int|string|null>  $position
     * @param  bool  $isInclusive
     * @return \Illuminate\Database\Query\Builder
     *
     * @throws \UnexpectedValueException
     */
    public static function after(Builder $query, string $table, string $target, bool $isTargetFirst, array $position, bool $isInclusive = false): Builder
    {
        $columns = [
            [$table . self::GRANTEE_TYPE, Keyset::TEXT],
            [$table . self::GRANTEE_ID, Keyset::TEXT],
            [$table . '.tenant_type', Keyset::TAGGED],
            [$table . '.tenant_id', Keyset::TAGGED],
            [$table . '.application', Keyset::TAGGED],
            [$table . '.include_subtree', Keyset::FLAG],
        ];

        $columns = $isTargetFirst ? [[$table . '.' . $target, Keyset::TEXT], ...$columns] : [...$columns, [$table . '.' . $target, Keyset::TEXT]];

        return Keyset::after($query, $columns, $position, $isInclusive);
    }

    /**
     * Limit a query of role permission edges, ordered by permission then role,
     * to the edges after the position, or at it too when asked.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  list<bool|int|string|null>  $position
     * @param  bool  $isInclusive
     * @return \Illuminate\Database\Query\Builder
     *
     * @throws \UnexpectedValueException
     */
    public static function afterEdge(Builder $query, array $position, bool $isInclusive = false): Builder
    {
        $table = Definitions::edges();

        return Keyset::after($query, [[$table . '.permission_id', Keyset::TEXT], [$table . '.role_id', Keyset::TEXT]], $position, $isInclusive);
    }

    /**
     * Return the position of a stored row in a grant query ordered as
     * `ordered()` orders it: its target first or last, as asked, around its
     * grantee and scope.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\GrantRow  $row
     * @param  bool  $isTargetFirst
     * @return list<bool|int|string|null>
     */
    public static function positionOf(GrantRow $row, bool $isTargetFirst): array
    {
        return $isTargetFirst ? [$row->targetId, ...$row->orderKey()] : [...$row->orderKey(), $row->targetId];
    }

    /**
     * Return the position, in a grant query ordered as `ordered()` orders it,
     * of the stored row a review's row starts from, read from the row's sort
     * key (see `RowCollector`): its target, or for a route through roles the
     * role granted, the first of its route, around its grantee and scope.
     *
     * @param  list<bool|int|string|null>  $key
     * @param  bool  $isTargetFirst
     * @return list<bool|int|string|null>
     */
    public static function positionAt(array $key, bool $isTargetFirst): array
    {
        $stored = \array_slice($key, RowCollector::STORED, RowCollector::ROUTE - RowCollector::STORED);

        return $isTargetFirst ? [$key[RowCollector::TARGET] ?? null, ...$stored] : [...$stored, $key[RowCollector::ROUTE] ?? null];
    }

    /**
     * Return the position, in a query of role permission edges, of the edge a
     * review's row starts from, read from the row's sort key: its permission,
     * then its role.
     *
     * @param  list<bool|int|string|null>  $key
     * @return list<bool|int|string|null>
     */
    public static function edgeAt(array $key): array
    {
        return [$key[RowCollector::TARGET] ?? null, $key[RowCollector::STORED + 1] ?? null];
    }
}
