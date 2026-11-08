<?php

declare(strict_types = 1);

namespace Tests\Fixtures;

use Illuminate\Database\Query\Builder;
use Illuminate\Database\Query\Grammars\SQLiteGrammar;

/**
 * A SQLite grammar that compiles a lock into an order by the name, last first,
 * so a locking read of a query with no order of its own returns its rows in the
 * reverse of the order a plain read returns them, as two reads of the same rows
 * may on any database.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ReversingLockGrammar extends SQLiteGrammar
{
    /**
     * Compile a lock into an order by the name, last first.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  bool|string  $value
     * @return string
     */
    #[\Override]
    protected function compileLock(Builder $query, $value): string
    {
        return 'order by name desc';
    }
}
