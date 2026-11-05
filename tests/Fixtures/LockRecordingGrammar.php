<?php

declare(strict_types = 1);

namespace Tests\Fixtures;

use Illuminate\Database\Connection;
use Illuminate\Database\Query\Builder;
use Illuminate\Database\Query\Grammars\SQLiteGrammar;

/**
 * SQLite query grammar that records each query compiled with a row lock.
 *
 * SQLite has no row locks, so its grammar drops `lockForUpdate()` from the SQL
 * and a query listener cannot see it. This grammar records the table and the
 * bindings of each locking query instead, and still compiles no lock clause.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class LockRecordingGrammar extends SQLiteGrammar
{
    /**
     * Create a new grammar instance.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  \ArrayObject<int, array{string, list<mixed>}>  $locks
     */
    public function __construct(

        // The connection the grammar compiles for.
        Connection $connection,

        /** The locking queries recorded so far, as table and bindings. */
        private readonly \ArrayObject $locks,
    ) {
        parent::__construct($connection);
    }

    /**
     * Record the locking query and compile no lock clause.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  bool|string  $value
     * @return string
     */
    #[\Override]
    protected function compileLock(Builder $query, $value): string
    {
        /** @var string $table */
        $table = $query->from;

        $this->locks->append([$table, $query->getBindings()]);

        return '';
    }
}
