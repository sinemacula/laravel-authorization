<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Database;

use Illuminate\Contracts\Database\Query\Builder;

/**
 * Limits a grant query to the grants that hold in an application: those made
 * for every application, and those made for it (AUTHZ-5.6).
 *
 * Without an application only the grants made for every application count, as
 * without a tenant only platform-wide grants do.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class GrantApplications
{
    /**
     * Limit the query to the rows of the table that hold in the application.
     *
     * @template TQuery of \Illuminate\Contracts\Database\Query\Builder
     *
     * @param  TQuery  $query
     * @param  string  $table
     * @param  string|null  $application
     * @return TQuery
     */
    public static function only(Builder $query, string $table, ?string $application): Builder
    {
        $query->where(static function (Builder $query) use ($table, $application): void {
            $query->whereNull($table . '.application');

            if ($application === null) {
                return;
            }

            $query->orWhere($table . '.application', $application);
        });

        return $query;
    }
}
