<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;

/**
 * Races a call with a second database session, on MySQL and PostgreSQL, so a
 * test can show what the call's locks hold back and what it reads of a change
 * committed while it runs. SQLite has one writer, so a race is skipped there.
 *
 * A race must run outside the test's transaction, or the second session sees
 * none of the rows the test made: the test class leaves its raced tests out of
 * `connectionsToTransact()`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-require-extends \Tests\TestCase
 */
trait RacesAnotherSession
{
    /** @var string The name of the second session's connection. */
    private const string OTHER_SESSION = 'other_session';

    /**
     * Run the race with a second session that waits no longer than a second for
     * a lock, emptying the tables once it ends; skip it on SQLite.
     *
     * @param  list<string>  $tables
     * @param  \Closure(): void  $race
     * @return void
     *
     * @throws \Throwable
     */
    protected function raceOrSkip(array $tables, \Closure $race): void
    {
        $connection = DB::connection();

        if ($connection->getDriverName() === 'sqlite') {
            self::markTestSkipped('SQLite has one writer, so nothing commits while a call runs.');
        }

        config(['database.connections.' . self::OTHER_SESSION => $connection->getConfig()]);

        $other = DB::connection(self::OTHER_SESSION);

        $other->statement($other->getDriverName() === 'mysql' ? 'set session innodb_lock_wait_timeout = 1' : 'set lock_timeout = \'1s\'');

        try {
            $race();
        } finally {
            // The roles' parent key restricts a delete, so the hierarchy goes
            // first.
            if (\in_array('roles', $tables, true)) {
                DB::table('roles')->update(['parent_id' => null]);
            }

            foreach ($tables as $table) {
                DB::table($table)->delete();
            }

            DB::purge(self::OTHER_SESSION);
        }
    }

    /**
     * Run the call and, once it runs a statement of the kind on the table, the
     * concurrent call on the second session, as the package's connection,
     * rolled back, and assert the concurrent call waited for a lock until it
     * gave up.
     *
     * @param  string  $kind
     * @param  string  $table
     * @param  \Closure(): mixed  $call
     * @param  \Closure(\Illuminate\Database\Connection): mixed  $concurrent
     * @return void
     */
    protected static function assertWaits(string $kind, string $table, \Closure $call, \Closure $concurrent): void
    {
        /** @var \ArrayObject<int, \Throwable> $thrown */
        $thrown = new \ArrayObject;
        $isDone = false;

        DB::listen(static function (QueryExecuted $query) use ($kind, $table, $concurrent, $thrown, &$isDone): void {
            $sql = \str_replace(['"', '`'], '', $query->sql);

            if ($isDone || $query->connectionName === self::OTHER_SESSION || !\str_starts_with($sql, $kind . ' ') || !\str_contains($sql, ' ' . $table . ' ')) {
                return;
            }

            $isDone = true;

            self::concurrently($concurrent, $thrown);
        });

        $call();

        $waited = $thrown->getArrayCopy()[0] ?? null;

        self::assertMatchesRegularExpression('/lock timeout|Lock wait timeout/', $waited?->getMessage() . ' ' . $waited?->getPrevious()?->getMessage());
    }

    /**
     * Run the call, committing the change on the second session once the call
     * has made its first read inside its transaction, which fixes its snapshot
     * on MySQL.
     *
     * @param  \Closure(): mixed  $call
     * @param  \Closure(\Illuminate\Database\Connection): mixed  $change
     * @return mixed
     */
    protected static function afterFirstRead(\Closure $call, \Closure $change): mixed
    {
        $package = DB::connection();
        $isDone  = false;

        DB::listen(static function (QueryExecuted $query) use ($package, $change, &$isDone): void {
            if ($isDone || $query->connectionName !== $package->getName() || $package->transactionLevel() === 0 || !\str_starts_with(\strtolower($query->sql), 'select')) {
                return;
            }

            $isDone = true;

            $change(DB::connection(self::OTHER_SESSION));
        });

        return $call();
    }

    /**
     * Run the call on the second session, as the package's connection, inside a
     * transaction rolled back once it ends, keeping what it threw.
     *
     * @param  \Closure(\Illuminate\Database\Connection): mixed  $call
     * @param  \ArrayObject<int, \Throwable>  $thrown
     * @return void
     */
    private static function concurrently(\Closure $call, \ArrayObject $thrown): void
    {
        /** @var \Illuminate\Database\Connection $other */
        $other   = DB::connection(self::OTHER_SESSION);
        $package = config('authorization.connection');

        config(['authorization.connection' => self::OTHER_SESSION]);
        $other->beginTransaction();

        try {
            $call($other);
        } catch (\Throwable $exception) {
            $thrown->append($exception);
        } finally {
            $other->rollBack();
            config(['authorization.connection' => $package]);
        }
    }
}
