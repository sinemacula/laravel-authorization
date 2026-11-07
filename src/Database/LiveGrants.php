<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Database;

use Illuminate\Contracts\Database\Query\Builder;
use Illuminate\Support\Carbon;

/**
 * Limits a query to the grant rows that still count: those with no expiry, and
 * those whose expiry has not passed.
 *
 * Every grant table, and the role permission pivot, stores its expiry in UTC,
 * so the comparison is against the current UTC instant. An expired row stops
 * counting the moment its expiry passes, with no sweeper; `authorization:prune`
 * only removes it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class LiveGrants
{
    /**
     * Limit the query to the rows of the table whose expiry has not passed at
     * the instant given, else now.
     *
     * @template TQuery of \Illuminate\Contracts\Database\Query\Builder
     *
     * @param  TQuery  $query
     * @param  string  $table
     * @param  \Illuminate\Support\Carbon|null  $now
     * @return TQuery
     */
    public static function only(Builder $query, string $table, ?Carbon $now = null): Builder
    {
        $at = $now ?? Carbon::now('UTC');

        $query->where(static function (Builder $query) use ($table, $at): void {
            $query->whereNull($table . '.expires_at')->orWhere($table . '.expires_at', '>', $at);
        });

        return $query;
    }
}
