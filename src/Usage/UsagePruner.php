<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Usage;

use Illuminate\Database\Query\Builder;
use Illuminate\Support\Carbon;
use SineMacula\Laravel\Authorization\Config\TableNames;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Database\KeyAsText;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;

/**
 * Prunes the package's grant usage tables (N102): the row of every route whose
 * stored grant no longer exists, matched on the columns that make the grant
 * unique (its table, the key it grants, its grantee, and its tenant and
 * application as stored, a null matching a null), and every coverage period
 * that ended before the retention.
 *
 * A grant revoked and made again is a new row, so the row of its route is kept
 * while the grant exists, and its old use is ignored by its creation (see
 * `ObservedUse::isOf()`) until the next observation replaces it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class UsagePruner
{
    /**
     * Remove, or with `$pretend` count, the usage of routes whose grant no
     * longer exists and the coverage that ended more than the retention's days
     * ago; return how many of each.
     *
     * @param  int  $retention
     * @param  bool  $pretend
     * @return array{int, int}
     */
    public static function prune(int $retention, bool $pretend = false): array
    {
        $usage = 0;

        foreach (GrantTarget::cases() as $kind) {
            $orphans = self::orphansOf(self::table('grant_usage'), $kind);

            $usage += $pretend ? $orphans->count() : $orphans->delete();
        }

        $expired = self::table('usage_coverage')
            ->where('covered_until', '<', Carbon::now('UTC')->subDays($retention)->format('Y-m-d H:i:s'));

        return [$usage, $pretend ? $expired->count() : $expired->delete()];
    }

    /**
     * Limit the query of the usage table to the rows of routes starting from a
     * grant of the kind that no longer exists, the grant's key compared as text
     * (see `KeyAsText`).
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  \SineMacula\Laravel\Authorization\Enums\GrantTarget  $kind
     * @return \Illuminate\Database\Query\Builder
     */
    public static function orphansOf(Builder $query, GrantTarget $kind): Builder
    {
        $usage  = \is_string($query->from) ? $query->from : '';
        $grants = $kind->table();

        return $query
            ->where($usage . '.grant_source', $kind->value)
            ->whereNotExists(static function (Builder $exists) use ($usage, $grants, $kind): void {
                $exists->selectRaw('1')
                    ->from($grants)
                    ->whereColumn(new KeyAsText($grants . '.' . $kind->column()), $usage . '.grant_id')
                    ->whereColumn($grants . '.authorizable_type', $usage . '.authorizable_type')
                    ->whereColumn($grants . '.authorizable_id', $usage . '.authorizable_id');

                foreach (RouteSources::SCOPE as $column) {
                    self::same($exists, $grants . '.' . $column, $usage . '.' . $column);
                }
            });
    }

    /**
     * Limit the query to the rows whose two columns hold the same value, a null
     * matching a null.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  string  $one
     * @param  string  $other
     * @return void
     */
    private static function same(Builder $query, string $one, string $other): void
    {
        $query->where(static function (Builder $same) use ($one, $other): void {
            $same->whereColumn($one, $other)->orWhere(static function (Builder $both) use ($one, $other): void {
                $both->whereNull($one)->whereNull($other);
            });
        });
    }

    /**
     * Query the configured table on the package's connection, on the write
     * connection.
     *
     * @param  non-empty-string  $key
     * @return \Illuminate\Database\Query\Builder
     */
    private static function table(string $key): Builder
    {
        return AuthorizationConnection::connection()->table(TableNames::get($key))->useWritePdo();
    }
}
