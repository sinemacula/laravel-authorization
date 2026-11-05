<?php

declare(strict_types = 1);

namespace Tests\Fixtures;

use Illuminate\Database\Query\Builder;

/**
 * Process-wide record of the base query builders a fixture model creates.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class QueryRecorder
{
    /** @var list<\Illuminate\Database\Query\Builder> Base query builders recorded since the last reset. */
    private static array $queries = [];

    /**
     * Record a base query builder.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @return void
     */
    public static function record(Builder $query): void
    {
        self::$queries[] = $query;
    }

    /**
     * Return the base query builders recorded since the last reset.
     *
     * @return list<\Illuminate\Database\Query\Builder>
     */
    public static function recorded(): array
    {
        return self::$queries;
    }

    /**
     * Forget the recorded base query builders.
     *
     * @return void
     */
    public static function reset(): void
    {
        self::$queries = [];
    }
}
