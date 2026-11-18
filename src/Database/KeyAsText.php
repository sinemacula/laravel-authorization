<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Database;

use Illuminate\Contracts\Database\Query\Expression;
use Illuminate\Database\Grammar;
use Illuminate\Database\Query\Grammars\MySqlGrammar;
use Illuminate\Database\Query\Grammars\PostgresGrammar;

/**
 * A key column read as text, so it compares with a key the grant tables store
 * as a string on the driver of the query it is compiled for: PostgreSQL casts
 * its `uuid` or integer, MySQL concatenates it with an empty string, which an
 * integer otherwise compares as a double, and SQLite compares the two as they
 * are.
 *
 * The column is wrapped by the grammar the expression is compiled with, so it
 * goes wherever a query takes a column, such as either side of `whereColumn()`,
 * with no raw SQL built outside the grammar.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class KeyAsText implements Expression
{
    /**
     * Create a new key read as text.
     *
     * @param  string  $column
     */
    public function __construct(

        /** The key column, qualified by its table where the query needs it. */
        private string $column,
    ) {}

    /**
     * Return the column as the grammar wraps it, read as text on PostgreSQL and
     * MySQL.
     *
     * @param  \Illuminate\Database\Grammar  $grammar
     * @return string
     */
    #[\Override]
    public function getValue(Grammar $grammar): string
    {
        $wrapped = $grammar->wrap($this->column);

        // concat() keeps the compared column's collation; a cast would take the
        // connection's.
        return match (true) {
            $grammar instanceof PostgresGrammar => "cast({$wrapped} as text)",
            $grammar instanceof MySqlGrammar    => "concat({$wrapped}, '')",
            default                             => $wrapped,
        };
    }
}
