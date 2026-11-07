<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Query;

/**
 * Joins the conditions `whereAuthorized()` compiles, simplifying as it goes: a
 * conjunction drops every condition every row meets and is no row's when one
 * is, a disjunction drops every condition no row meets and is every row's when
 * one is, and a negation of either constant is the other.
 *
 * A negation treats a condition the database cannot decide (null) as met before
 * negating it, so a condition that could not be decided never lets a row
 * through by being negated.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class Conditions
{
    /**
     * Return the conjunction of the conditions.
     *
     * @param  list<string>  $conditions
     * @return string
     */
    public static function all(array $conditions): string
    {
        $conditions = \array_values(\array_unique(\array_diff($conditions, [QueryAuthorizer::EVERY_ROW])));

        return \in_array(QueryAuthorizer::NO_ROW, $conditions, true) ? QueryAuthorizer::NO_ROW : self::joined($conditions, ' AND ', QueryAuthorizer::EVERY_ROW);
    }

    /**
     * Return the disjunction of the conditions.
     *
     * @param  list<string>  $conditions
     * @return string
     */
    public static function any(array $conditions): string
    {
        $conditions = \array_values(\array_unique(\array_diff($conditions, [QueryAuthorizer::NO_ROW])));

        return \in_array(QueryAuthorizer::EVERY_ROW, $conditions, true) ? QueryAuthorizer::EVERY_ROW : self::joined($conditions, ' OR ', QueryAuthorizer::NO_ROW);
    }

    /**
     * Return the negation of the condition, one the database cannot decide
     * counting as met.
     *
     * @param  string  $condition
     * @return string
     */
    public static function not(string $condition): string
    {
        return match ($condition) {
            QueryAuthorizer::EVERY_ROW => QueryAuthorizer::NO_ROW,
            QueryAuthorizer::NO_ROW    => QueryAuthorizer::EVERY_ROW,
            default                    => 'NOT COALESCE(' . $condition . ', ' . QueryAuthorizer::EVERY_ROW . ')',
        };
    }

    /**
     * Return the conditions joined by the operator, grouped, the one condition
     * alone, or the condition given for none.
     *
     * @param  list<string>  $conditions
     * @param  string  $operator
     * @param  string  $none
     * @return string
     */
    private static function joined(array $conditions, string $operator, string $none): string
    {
        return match (\count($conditions)) {
            0       => $none,
            1       => $conditions[0],
            default => '(' . \implode($operator, $conditions) . ')',
        };
    }
}
