<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Database;

use Illuminate\Contracts\Database\Query\Expression;
use Illuminate\Database\Grammar;
use Illuminate\Database\Query\Grammars\PostgresGrammar;

/**
 * A definition key column read as text, so it compares with a grantee key
 * column on the driver of the query it is compiled for: PostgreSQL casts its
 * `uuid`, any other database stores the key as text already.
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
     * Return the column as the grammar wraps it, cast to text on PostgreSQL.
     *
     * @param  \Illuminate\Database\Grammar  $grammar
     * @return string
     */
    #[\Override]
    public function getValue(Grammar $grammar): string
    {
        $wrapped = $grammar->wrap($this->column);

        return $grammar instanceof PostgresGrammar ? "cast({$wrapped} as text)" : $wrapped;
    }
}
