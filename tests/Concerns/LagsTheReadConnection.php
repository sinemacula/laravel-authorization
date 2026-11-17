<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Database\SQLiteConnection;

/**
 * Gives the package's second connection a read connection that lags behind it:
 * a copy of every table as it stands, which no later write reaches.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-require-extends \Tests\TestCase
 */
trait LagsTheReadConnection
{
    use UsesAnAuthorizationConnection;

    /**
     * Copy the second connection's tables to a new read connection for it.
     *
     * @return void
     */
    protected static function lagTheReadConnection(): void
    {
        $connection = self::authorizationConnection();
        $replica    = new SQLiteConnection(new \PDO('sqlite::memory:'));

        /** @var list<object{name: string, sql: string}> $tables */
        $tables = $connection->select('select name, sql from sqlite_master where type = \'table\' and name not like \'sqlite_%\'');

        foreach ($tables as $table) {
            $replica->statement($table->sql);
            $replica->table($table->name)->insert($connection->table($table->name)->get()->map(static fn (object $row): array => (array) $row)->all());
        }

        $connection->setReadPdo($replica->getPdo());
    }
}
