<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Query;

use Illuminate\Database\Connection;
use Illuminate\Database\Query\Builder;
use SineMacula\Laravel\Authorization\Query\Contracts\Dialect;

/**
 * Writes a query that a scope's condition nests as SQL with every value
 * inlined, and tells where a condition that nests a read of the authorization
 * tables must run so it reads what `check()` reads.
 *
 * Each binding is replaced, in order, by the literal the dialect writes for it
 * (`Dialect::parameter()`), which the database reads as it reads the value
 * bound, and in which no character of a string is written as it is: a quote, a
 * backslash, a question mark or a NUL byte in a tenant, an application or a
 * policy is never read as SQL. A query whose text holds a question mark that is
 * not a placeholder, or a binding no literal can stand for, is not written.
 *
 * `check()` reads the authorization tables on the write connection, so a
 * condition that nests a read of them (a record attachment,
 * `RecordAttachments`, or a subtree, `TenantMembership`, told by the alias each
 * is read under) must run there too. It does on a connection with no separate
 * read connection, or inside a transaction, where Laravel reads on the write
 * connection; otherwise the query carrying it must be put on the write
 * connection, which only the query the builder is running itself can be: its
 * `select`, `cursor`, `exists`, `update` or `delete`, which passes its
 * `useWritePdo` to the connection only once it has compiled the condition.
 * Which is running is read from the call stack: a query nested in another,
 * compiled to text another takes in, or compiled for no execution is not.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class InlinedQuery
{
    /** @var list<string> The methods of a query builder that run the query they compile, choosing its connection after compiling it. */
    private const array RUNS = ['runSelect', 'cursor', 'exists', 'update', 'delete', 'updateFrom'];

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

    /**
     * Determine whether a condition nests a read of the authorization tables:
     * the attachments or a subtree, by the alias each is read under.
     *
     * @param  string  $condition
     * @return bool
     */
    public static function readsAuthorizationTables(string $condition): bool
    {
        return \str_contains($condition, RecordAttachments::ALIAS) || \str_contains($condition, TenantMembership::ALIAS);
    }

    /**
     * Determine whether the query being compiled is the one its builder is
     * running now, rather than one nested in another query, or compiled to text
     * another query takes in, or for no execution at all.
     *
     * @param  \Illuminate\Database\Query\Builder  $query
     * @return bool
     */
    public static function isRunning(Builder $query): bool
    {
        $frames = \debug_backtrace(\DEBUG_BACKTRACE_PROVIDE_OBJECT | \DEBUG_BACKTRACE_IGNORE_ARGS);

        // A cursor compiles the query in a generator of its own, the only
        // closure of the builder that compiles it, which PHP names `{closure}`,
        // or after the method defining it.
        $isRun = static fn (array $frame): bool => ($frame['object'] ?? null) === $query
            && (\in_array($frame['function'], self::RUNS, true) || (\str_starts_with($frame['function'], '{closure') && ($frame['class'] ?? null) === Builder::class));

        return \array_filter($frames, $isRun) !== [];
    }
}
