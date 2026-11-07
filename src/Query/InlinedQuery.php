<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Query;

use Illuminate\Database\Connection;
use Illuminate\Database\Query\Builder;
use SineMacula\Laravel\Authorization\Query\Contracts\Dialect;

/**
 * Writes a query that a scope's condition nests as SQL with every value
 * inlined, and tells whether a nested read of the authorization tables reads
 * what `check()` reads.
 *
 * Each binding is replaced, in order, by the literal the dialect writes for it
 * (`Dialect::parameter()`), which the database reads as it reads the value
 * bound, and in which no character of a string is written as it is: a quote, a
 * backslash, a question mark or a NUL byte in a tenant, an application or a
 * policy is never read as SQL. A query whose text holds a question mark that is
 * not a placeholder, or a binding no literal can stand for, is not written.
 *
 * `check()` reads the authorization tables on the write connection, so a
 * condition that nests a read of them must run there too: on a connection with
 * no separate read connection, or inside a transaction, where Laravel reads on
 * the write connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class InlinedQuery
{
    /**
     * Return the query's SQL with each binding inlined as the dialect writes
     * it, or null when that cannot be written exactly.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @param  \SineMacula\Laravel\Authorization\Query\Contracts\Dialect  $dialect
     * @return string|null
     */
    public static function sqlOf(Builder $query, Dialect $dialect): ?string
    {
        $parts    = \explode('?', $query->toSql());
        $literals = \array_map($dialect->parameter(...), \array_values($query->getConnection()->prepareBindings($query->getBindings())));

        if (\count($parts) !== \count($literals) + 1 || \in_array(null, $literals, true)) {
            return null;
        }

        $sql = \array_shift($parts);

        foreach ($parts as $index => $part) {
            $sql .= $literals[$index] . $part;
        }

        return $sql;
    }

    /**
     * Determine whether a query run on the connection reads where `check()`
     * reads the authorization tables, on the write connection: the connection
     * has no separate read connection, or is in a transaction.
     *
     * @param  \Illuminate\Database\Connection  $connection
     * @return bool
     */
    public static function isReadOnWrite(Connection $connection): bool
    {
        $read = $connection->getRawReadPdo();

        return $read === null || $read === $connection->getRawPdo() || $connection->transactionLevel() > 0;
    }
}
