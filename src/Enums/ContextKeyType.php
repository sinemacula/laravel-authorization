<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Enums;

use SineMacula\Laravel\Authorization\Evaluation\ConditionEvaluator;

/**
 * The type of a declared context key, which decides the operators a condition
 * may test it with (N25).
 *
 * The `_if_exists` form of an operator suits the types its operator suits, and
 * `null` suits every type. A value of the wrong type found at evaluation is
 * still undecidable, whatever the key declares.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum ContextKeyType: string
{
    /** A string, such as a guard or a route name. */
    case STRING = 'string';

    /** A number, integer or float. */
    case NUMBER = 'number';

    /** A boolean, or one of its string forms. */
    case BOOL = 'bool';

    /** An instant, such as `environment.time`. */
    case TIME = 'time';

    /** An IPv4 or IPv6 address, such as `request.ip`. */
    case IP = 'ip';

    /** A list of scalars, such as a set of groups. */
    case LIST = 'list';

    /**
     * Return the operators a condition may test a key of this type with,
     * besides `null` and the `_if_exists` forms.
     *
     * @return list<string>
     */
    public function operators(): array
    {
        return match ($this) {
            self::STRING => ['eq', 'neq', 'in', 'not_in', 'starts_with', 'ends_with', 'like'],
            self::NUMBER => ['eq', 'neq', 'in', 'not_in', 'gt', 'gte', 'lt', 'lte'],
            self::BOOL   => ['eq', 'neq', 'bool'],
            self::TIME   => ['before', 'after', 'between'],
            self::IP     => ['eq', 'neq', 'in', 'not_in', 'ip_in', 'ip_not_in'],
            self::LIST   => ['any_value_in', 'all_values_in'],
        };
    }

    /**
     * Determine whether a condition may test a key of this type with the
     * operator, written as in a policy document (`ip_in_if_exists` suits the
     * types `ip_in` suits). An unknown operator suits no type.
     *
     * @param  string  $name
     * @return bool
     */
    public function suits(string $name): bool
    {
        $operator = ConditionEvaluator::operatorOf($name);

        return $operator === 'null' || ($operator !== null && \in_array($operator, $this->operators(), true));
    }
}
