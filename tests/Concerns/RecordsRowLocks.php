<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Database\Connection;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use Tests\Fixtures\LockRecordingGrammar;

/**
 * Records the queries that take a row lock on a connection, whatever its
 * driver, and the tables a call locks rows of.
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
     * Return the tables the call locked rows of, exclusively or shared, each
     * once, in order: as the grammar records them on SQLite, else as the locks
     * in the SQL.
     *
     * @param  \Closure(): mixed  $call
     * @return list<string>
     */
    protected function lockedTables(\Closure $call): array
    {
        $locks = $this->recordRowLocks();

        DB::enableQueryLog();
        DB::flushQueryLog();

        $call();

        $log = DB::getQueryLog();

        DB::disableQueryLog();

        $tables = \array_map(static fn (array $lock): string => $lock[0], $locks->getArrayCopy());

        foreach ($log as $entry) {
            if (\preg_match('/ for share| lock in share mode/i', $entry['query']) !== 1) {
                continue;
            }

            $tables[] = self::lockedTable($entry['query']);
        }

        $tables = \array_values(\array_unique($tables));

        \sort($tables);

        return $tables;
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
