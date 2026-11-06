<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;

/**
 * Interleaves a concurrent change with the insert-or-ignore writes into a
 * table, whatever the driver, so a test can reach what a writer does when its
 * insert is ignored and the row it would read back is gone: a row a concurrent
 * call removed in between, or, on MySQL, a foreign key failure that `INSERT
 * IGNORE` turns into a warning.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-require-extends \Tests\TestCase
 */
trait InterleavesWrites
{
    /**
     * Once each of the first inserts-or-ignore into the table runs, as many as
     * the removals, run the removal, so the locking read that follows finds no
     * row; and once each of the first such reads runs, as many as the restores,
     * run the restoration, so the next insert is ignored too. Return the
     * insert-or-ignore statements seen.
     *
     * @param  string  $table
     * @param  \Closure(): void  $remove
     * @param  \Closure(): void  $restore
     * @param  int  $removes
     * @param  int  $restores
     * @return \ArrayObject<int, string>
     */
    protected static function interleaveWrites(string $table, \Closure $remove, \Closure $restore, int $removes = 1, int $restores = 0): \ArrayObject
    {
        /** @var \ArrayObject<int, string> $inserts */
        $inserts = new \ArrayObject;
        $remove  = self::limitedTo($remove, $removes);
        $restore = self::limitedTo($restore, $restores);

        DB::listen(static function (QueryExecuted $query) use ($table, $remove, $restore, $inserts): void {
            $sql  = \strtolower($query->sql);
            $kind = match (true) {
                !\str_contains($sql, $table)     => null,
                \str_starts_with($sql, 'select') => 'read',
                \str_starts_with($sql, 'insert') => \str_contains($sql, ' ignore') || \str_contains($sql, 'on conflict') ? 'ignorable' : null,
                default                          => null,
            };

            if ($kind === 'read') {
                $restore();

                return;
            }

            if ($kind !== 'ignorable') {
                return;
            }

            $inserts->append($sql);
            $remove();
        });

        return $inserts;
    }

    /**
     * Return the change, run at most the given number of times.
     *
     * @param  \Closure(): void  $change
     * @param  int  $times
     * @return \Closure(): void
     */
    private static function limitedTo(\Closure $change, int $times): \Closure
    {
        $runs = new \ArrayObject;

        return static function () use ($change, $times, $runs): void {
            if ($runs->count() >= $times) {
                return;
            }

            $runs->append(true);
            $change();
        };
    }
}
