<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Database;

use Illuminate\Contracts\Database\Query\Expression;
use Illuminate\Database\Grammar;

/**
 * A raw clause the package composes from identifiers the query's grammar has
 * wrapped, SQL literals and `?` placeholders, never from a value, which is
 * always bound.
 *
 * Laravel's own expression and its raw clauses take literal SQL alone, and an
 * identifier wrapped at run time is never literal, so the clauses that name a
 * configured table or column are handed over as this expression instead.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ComposedExpression implements Expression
{
    /**
     * Create a new composed expression.
     *
     * @param  string  $sql
     */
    public function __construct(

        /** The composed SQL. */
        private string $sql,
    ) {}

    /**
     * Return the composed SQL.
     *
     * @param  \Illuminate\Database\Grammar  $grammar
     * @return string
     */
    #[\Override]
    public function getValue(Grammar $grammar): string
    {
        return $this->sql;
    }
}
