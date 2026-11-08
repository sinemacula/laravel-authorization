<?php

declare(strict_types = 1);

namespace Tests\Fixtures;

use Illuminate\Database\Query\Builder;
use Illuminate\Database\Query\Grammars\SQLiteGrammar;

/**
 * SQLite query grammar under which a locking read finds nothing.
 *
 * SQLite compiles no row lock, so a read under a lock and one without always
 * agree there. While it is emptying, this grammar compiles a lock into `limit
 * 0`, so a test can make the two reads differ, as a snapshot older than the
 * locks would on MySQL; a query keeps the grammar it was built with, so the
 * switch reaches queries built before it was thrown.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class EmptyLockGrammar extends SQLiteGrammar
{
    /** @var bool Whether a locking read finds nothing. */
    public bool $isEmptying = true;

    /**
     * Compile a lock into a limit that reads nothing while emptying, and into
     * nothing otherwise, as SQLite's own grammar does.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  bool|string  $value
     * @return string
     */
    #[\Override]
    protected function compileLock(Builder $query, $value): string
    {
        return $this->isEmptying ? 'limit 0' : '';
    }
}
