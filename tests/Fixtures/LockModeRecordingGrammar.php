<?php

declare(strict_types = 1);

namespace Tests\Fixtures;

use Illuminate\Database\Connection;
use Illuminate\Database\Query\Builder;
use Illuminate\Database\Query\Grammars\SQLiteGrammar;

/**
 * SQLite query grammar that records each query compiled with a row lock, and
 * whether the lock is for update or shared, which SQLite compiles neither of.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class LockModeRecordingGrammar extends SQLiteGrammar
{
    /**
     * Create a new grammar instance.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @param  \ArrayObject<int, array{0: string, 1: bool, 2: list<mixed>}>  $locks
     */
    public function __construct(

        // The connection the grammar compiles for.
        Connection $connection,

        /** The locking queries recorded so far, as table, whether for update, and bindings. */
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

        $this->locks->append([$table, $value === true, $query->getBindings()]);

        return '';
    }
}
