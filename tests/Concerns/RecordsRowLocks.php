<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Database\Connection;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use Tests\Fixtures\LockRecordingGrammar;

/**
 * Records the queries that take a row lock on a connection, whatever its
 * driver.
 *
 * On MySQL and PostgreSQL a locking query carries `for update`, so a query
 * listener sees it. SQLite has no row locks and compiles none, so there the
 * connection is given a grammar that records each locking query as it is
 * compiled, and the default grammar is restored when the test ends.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-require-extends \Tests\TestCase
 */
trait RecordsRowLocks
{
    /**
     * Record each locking query run on the connection from here on, as its
     * table and bindings.
     *
     * @param  string|null  $name
     * @return \ArrayObject<int, array{string, list<mixed>}>
     */
    protected function recordRowLocks(?string $name = null): \ArrayObject
    {
        /** @var \ArrayObject<int, array{string, list<mixed>}> $locks */
        $locks = new \ArrayObject;

        /** @var \Illuminate\Database\Connection $connection */
        $connection = DB::connection($name);

        if ($connection->getDriverName() !== 'sqlite') {
            DB::listen(static function (QueryExecuted $query) use ($connection, $locks): void {
                if ($query->connectionName !== $connection->getName() || !\str_contains(\strtolower($query->sql), ' for update')) {
                    return;
                }

                $locks->append([self::lockedTable($query->sql), \array_values($query->bindings)]);
            });

            return $locks;
        }

        $connection->setQueryGrammar(new LockRecordingGrammar($connection, $locks));

        $this->beforeApplicationDestroyed(static fn () => self::restoreGrammar($connection));

        return $locks;
    }

    /**
     * Restore the connection's default query grammar.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return void
     */
    private static function restoreGrammar(Connection $connection): void
    {
        $connection->useDefaultQueryGrammar();
    }

    /**
     * Return the table a locking query reads.
     *
     * @param  string  $sql
     * @return string
     */
    private static function lockedTable(string $sql): string
    {
        \preg_match('/\bfrom\s+[`"]?(\w+)[`"]?/i', $sql, $matches);

        return $matches[1] ?? '';
    }
}
