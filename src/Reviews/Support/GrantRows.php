<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Reviews\Support;

use Illuminate\Database\Query\Builder;
use Illuminate\Support\Carbon;
use SineMacula\Laravel\Authorization\Config\TableNames;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Database\BreakGlassActivations;
use SineMacula\Laravel\Authorization\Database\ComposedExpression;
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
 * A review reads role grants together with the break-glass activations not
 * ended or expired at its instant, whether break-glass is enabled or not, since
 * one grants again once it is (see `held()`): each activation a row of its own,
 * ordered after a grant of the same role to the same grantee in the same scope,
 * and after each other by key. Each table is read by a query of its own, so
 * each filters, orders and limits on its own indexes: a page reads them as the
 * branches of one `union all`, merged in that order (see `pageOf()`).
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

    /** @var int The parts of a position naming a stored row's grantee and scope, before its activation's key. */
    private const int SCOPE_PARTS = 9;

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
     * Return the queries of the rows of the grant table of the kind as `of()`
     * reads them and, for roles, of the break-glass activations not ended or
     * expired at the run's instant, each read as a role grant row, activated
     * when created and updated, with its key and justification code, both null
     * on a grant's row; each keyed by its table and built by the callback,
     * given its table.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\ReviewRun  $run
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $target
     * @param  \Closure(\Illuminate\Database\Query\Builder, string): \Illuminate\Database\Query\Builder  $build
     * @return non-empty-array<string, \Illuminate\Database\Query\Builder>
     */
    public static function held(ReviewRun $run, GrantTarget $target, \Closure $build): array
    {
        if ($target !== GrantTarget::ROLE) {
            return [$target->table() => $build(self::of($target), $target->table())];
        }

        $grammar = AuthorizationConnection::connection()->getQueryGrammar();
        $nulls   = new ComposedExpression('null as ' . $grammar->wrap(BreakGlassActivations::ACTIVATION) . ', null as ' . $grammar->wrap('justification'));
        $queries = [$target->table() => $build(self::of($target)->addSelect($nulls), $target->table())];
        $table   = TableNames::get('break_glass');
        $columns = [$table . '.role_id as target_id', $table . self::GRANTEE_TYPE . ' as grantee_type', $table . self::GRANTEE_ID . ' as grantee_id'];

        foreach (self::COLUMNS as $column) {
            $columns[] = $table . '.' . match ($column) {
                'created_at', 'updated_at' => 'activated_at as ' . $column,
                default                    => $column,
            };
        }

        $columns[] = $table . '.id as ' . BreakGlassActivations::ACTIVATION;
        $columns[] = $table . '.justification';

        $activated = AuthorizationConnection::connection()->table($table)->useWritePdo()->select($columns);

        $queries[$table] = $build(BreakGlassActivations::unexpired($activated, $table, Carbon::instance($run->now)), $table);

        return $queries;
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
     * and its reach, for activations then by their key (see `held()`), then by
     * its target when asked to be last, so the order is total over the rows a
     * grant table can hold; a query of one target, which it matches exactly, is
     * not ordered by the target at all (null), so an index leading with the
     * target and the grantee serves the order.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  string  $table
     * @param  string  $target
     * @param  bool|null  $isTargetFirst
     * @return \Illuminate\Database\Query\Builder
     */
    public static function ordered(Builder $query, string $table, string $target, ?bool $isTargetFirst = true): Builder
    {
        if ($isTargetFirst === true) {
            ReviewOrder::by($query, $table . '.' . $target);
        }

        ReviewOrder::by($query, $table . self::GRANTEE_TYPE);
        ReviewOrder::by($query, $table . self::GRANTEE_ID);
        ReviewOrder::by($query, $table . '.tenant_type', true);
        ReviewOrder::by($query, $table . '.tenant_id', true);
        ReviewOrder::by($query, $table . '.application', true);

        $query->orderBy($table . '.include_subtree');

        if ($table === TableNames::get('break_glass')) {
            ReviewOrder::by($query, $table . '.id');
        }

        return $isTargetFirst === false ? ReviewOrder::by($query, $table . '.' . $target) : $query;
    }

    /**
     * Read every row of the grants of each chunk of the grantees, the queries
     * of a chunk given by the callback limited to the chunk, as stored rows of
     * the source, in the order of the chunks, one query a chunk and table, so
     * no query binds more than one chunk.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Support\Reference>  $grantees
     * @param  \Closure(list<\SineMacula\Laravel\Authorization\Support\Reference>): array<string, \Illuminate\Database\Query\Builder>  $queries
     * @param  string  $source
     * @return list<\SineMacula\Laravel\Authorization\Reviews\Support\GrantRow>
     */
    public static function allOf(array $grantees, \Closure $queries, string $source): array
    {
        $rows = [];

        foreach (\array_chunk($grantees, self::CHUNK) as $chunk) {
            foreach ($queries($chunk) as $query) {
                \array_push($rows, ...self::all($query, $source));
            }
        }

        return $rows;
    }

    /**
     * Read every row of the query as a stored row of the source, the grantee of
     * an edge being a role of the type given.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  string  $source
     * @param  string|null  $roleType
     * @return list<\SineMacula\Laravel\Authorization\Reviews\Support\GrantRow>
     */
    public static function all(Builder $query, string $source, ?string $roleType = null): array
    {
        $rows = [];

        foreach ($query->get() as $row) {
            $rows[] = GrantRow::from($row, $source, $roleType);
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
        return self::all($query->limit($limit), $source, $roleType);
    }

    /**
     * Read at most the limit of the rows of the queries together, in one query,
     * each query first limited by the callback, given its table, to where it
     * starts, then to the limit, and their rows merged in the review's order,
     * the target placed as the queries are ordered.
     *
     * @param  non-empty-array<string, \Illuminate\Database\Query\Builder>  $queries
     * @param  \Closure(\Illuminate\Database\Query\Builder, string): \Illuminate\Database\Query\Builder  $from
     * @param  string  $source
     * @param  int  $limit
     * @param  bool|null  $isTargetFirst
     * @param  string|null  $roleType
     * @return list<\SineMacula\Laravel\Authorization\Reviews\Support\GrantRow>
     *
     * @param-immediately-invoked-callable $from
     */
    public static function pageOf(array $queries, \Closure $from, string $source, int $limit, ?bool $isTargetFirst, ?string $roleType = null): array
    {
        $parts = \array_map(static fn (Builder $query, string $table): Builder => $from(clone $query, $table)->limit($limit), $queries, \array_keys($queries));
        $union = \array_shift($parts);

        // No order of the whole, so no database sorts or materialises it.
        foreach ($parts as $part) {
            $union->unionAll($part);
        }

        $rows = self::all($union, $source, $roleType);

        \usort($rows, static fn (GrantRow $one, GrantRow $other): int => ReviewOrder::compare(self::positionOf($one, $isTargetFirst), self::positionOf($other, $isTargetFirst)));

        return \array_slice($rows, 0, $limit);
    }

    /**
     * Limit a grant query ordered as `ordered()` orders it to the rows after
     * the position, or at it too when asked (see `Keyset`), the target first,
     * last or, for a query of one target, left out, as the query is ordered;
     * the activation's key a position holds is read only for activations.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  string  $table
     * @param  string  $target
     * @param  bool|null  $isTargetFirst
     * @param  list<bool|int|string|null>  $position
     * @param  bool  $isInclusive
     * @return \Illuminate\Database\Query\Builder
     *
     * @throws \UnexpectedValueException
     */
    public static function after(Builder $query, string $table, string $target, ?bool $isTargetFirst, array $position, bool $isInclusive = false): Builder
    {
        $columns = [
            [$table . self::GRANTEE_TYPE, Keyset::TEXT],
            [$table . self::GRANTEE_ID, Keyset::TEXT],
            [$table . '.tenant_type', Keyset::TAGGED],
            [$table . '.tenant_id', Keyset::TAGGED],
            [$table . '.application', Keyset::TAGGED],
            [$table . '.include_subtree', Keyset::FLAG],
        ];

        $at = ($isTargetFirst === true ? 1 : 0) + self::SCOPE_PARTS;

        if ($table === TableNames::get('break_glass')) {
            $columns[] = [$table . '.id', Keyset::TAGGED];
        } elseif (($position[$at] ?? null) === 1) {
            // A role grant comes before every activation of its scope, so only
            // a later scope follows one.
            \array_splice($position, $at);

            $isTargetFirst = $isTargetFirst === true ? true : null;
            $isInclusive   = false;
        } else {
            \array_splice($position, $at, 2);
        }

        $column  = [$table . '.' . $target, Keyset::TEXT];
        $columns = match ($isTargetFirst) {
            true  => [$column, ...$columns],
            false => [...$columns, $column],
            null  => $columns,
        };

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
     * grantee and scope, or none for a query of one target.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Support\GrantRow  $row
     * @param  bool|null  $isTargetFirst
     * @return list<bool|int|string|null>
     */
    public static function positionOf(GrantRow $row, ?bool $isTargetFirst): array
    {
        return match ($isTargetFirst) {
            true  => [$row->targetId, ...$row->orderKey()],
            false => [...$row->orderKey(), $row->targetId],
            null  => $row->orderKey(),
        };
    }

    /**
     * Return the position, in a grant query ordered as `ordered()` orders it,
     * of the stored row a review's row starts from, read from the row's sort
     * key (see `RowCollector`): its target, or for a route through roles the
     * role granted, the first of its route, around its grantee and scope; its
     * grantee and scope alone for a query of one target, so the stored row's
     * own key, never the target as a query spells it, says where to resume.
     *
     * @param  list<bool|int|string|null>  $key
     * @param  bool|null  $isTargetFirst
     * @return list<bool|int|string|null>
     */
    public static function positionAt(array $key, ?bool $isTargetFirst): array
    {
        $stored = \array_slice($key, RowCollector::STORED, RowCollector::ROUTE - RowCollector::STORED);

        return match ($isTargetFirst) {
            true  => [$key[RowCollector::TARGET] ?? null, ...$stored],
            false => [...$stored, $key[RowCollector::ROUTE] ?? null],
            null  => $stored,
        };
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
