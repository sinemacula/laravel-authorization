<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

use SineMacula\Laravel\Authorization\Support\AuthorizationLog;

/**
 * Internal helper evaluating the condition operators of a policy statement.
 *
 * Every operator answers with a match result rather than a boolean, so a test
 * that cannot be decided never reads as a plain "no":
 *
 * - a context value of the wrong type (a non-numeric value for `gt`, an
 *   unparseable time, a string that is not an IP address, a value that is not a
 *   list for `any_value_in`) is undecidable;
 * - an operand of the wrong type (`in` without a list, `between` without two
 *   bounds, a malformed range) or an unknown operator is invalid.
 *
 * Any operator but `null` may be written with the `_if_exists` suffix, which
 * makes a key the context lacks pass the test; the suffix changes nothing else
 * (see `operatorOf()`). It is not part of the public API.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ConditionEvaluator
{
    /** @var list<string> Every operator a condition may use. */
    public const array OPERATORS = [
        'eq',
        'neq',
        'in',
        'not_in',
        'starts_with',
        'ends_with',
        'like',
        'gt',
        'gte',
        'lt',
        'lte',
        'before',
        'after',
        'between',
        'bool',
        'null',
        'ip_in',
        'ip_not_in',
        'any_value_in',
        'all_values_in',
    ];

    /** @var string The suffix that makes a key the context lacks pass an operator's test. */
    public const string IF_EXISTS = '_if_exists';

    /** @var list<string> Operators whose operand is a glob pattern. */
    public const array PATTERN_OPERATORS = ['like'];

    /** @var list<string> Operators whose operand is never interpolated (a list, a pair of bounds or a flag). */
    private const array LITERAL_OPERAND_OPERATORS = ['in', 'not_in', 'between', 'null', 'any_value_in', 'all_values_in'];

    /** @var array<string, string> The family each operator is evaluated by. */
    private const array FAMILIES = [
        'eq'            => 'equality',
        'neq'           => 'equality',
        'in'            => 'membership',
        'not_in'        => 'membership',
        'starts_with'   => 'string',
        'ends_with'     => 'string',
        'like'          => 'string',
        'gt'            => 'number',
        'gte'           => 'number',
        'lt'            => 'number',
        'lte'           => 'number',
        'before'        => 'time',
        'after'         => 'time',
        'between'       => 'between',
        'bool'          => 'bool',
        'null'          => 'null',
        'ip_in'         => 'ip',
        'ip_not_in'     => 'ip',
        'any_value_in'  => 'values',
        'all_values_in' => 'values',
    ];

    /**
     * Return the operator an operator name tests with: the name itself, or the
     * name without its `_if_exists` suffix. Returns null for an unknown name,
     * including `null_if_exists`, since `null` already decides a missing key.
     *
     * @param  string  $name
     * @return string|null
     */
    public static function operatorOf(string $name): ?string
    {
        $operator = \str_ends_with($name, self::IF_EXISTS) ? \substr($name, 0, -\strlen(self::IF_EXISTS)) : $name;

        return \in_array($operator, self::OPERATORS, true) && ($operator !== 'null' || $operator === $name) ? $operator : null;
    }

    /**
     * Evaluate a single operator against the context value.
     *
     * @param  string  $operator
     * @param  mixed  $operand
     * @param  mixed  $actual
     * @return \SineMacula\Laravel\Authorization\Evaluation\MatchResult
     */
    public static function evaluate(string $operator, mixed $operand, mixed $actual): MatchResult
    {
        $family = self::FAMILIES[$operator] ?? null;

        return match ($family) {
            'between' => self::matchesBetween($operand, $actual),
            'bool'    => self::matchesBool($operand, $actual),
            'null'    => self::matchesNull($operand, $actual),
            null      => self::unknownOperator($operator),
            default   => self::matchesOperator($family, $operator, $operand, $actual),
        };
    }

    /**
     * Validate the literal operand of an operator, as written in a policy
     * document, returning the reason it is invalid or null when it is valid.
     *
     * A string operand containing a `${…}` reference is accepted for the
     * operators that interpolate their operand, since its value is known only
     * at evaluation time, unless it holds a NUL byte, which is then checked as
     * a literal one is. The operands of `in`, `not_in`, `between`, `null`,
     * `any_value_in` and `all_values_in` are never interpolated, so they are
     * always checked.
     *
     * @param  string  $operator
     * @param  mixed  $operand
     * @return string|null
     */
    public static function operandError(string $operator, mixed $operand): ?string
    {
        if (!\in_array($operator, self::OPERATORS, true)) {
            return "unknown operator '{$operator}'";
        }

        $deferred = \is_string($operand)
            && !\str_contains($operand, "\0")
            && ContextInterpolator::containsReference($operand)
            && !\in_array($operator, self::LITERAL_OPERAND_OPERATORS, true);

        return $deferred || ConditionOperands::isValid($operator, $operand) ? null : self::invalidOperand($operator);
    }

    /**
     * Log an unknown-operator line at debug level on the package's log channel.
     * Logging never aborts the check, which still fails closed: an unknown
     * operator makes the statement invalid.
     *
     * @param  string  $operator
     * @return void
     */
    public static function logUnknownOperator(string $operator): void
    {
        AuthorizationLog::debug("Unknown authorization condition operator '{$operator}': the statement is invalid.");
    }

    /**
     * Evaluate an operator of a family whose test depends on the operator
     * itself, not on its family alone.
     *
     * @param  'equality'|'ip'|'membership'|'number'|'string'|'time'|'values'  $family
     * @param  string  $operator
     * @param  mixed  $operand
     * @param  mixed  $actual
     * @return \SineMacula\Laravel\Authorization\Evaluation\MatchResult
     */
    private static function matchesOperator(string $family, string $operator, mixed $operand, mixed $actual): MatchResult
    {
        return match ($family) {
            'equality'   => self::matchesEquality($operator, $operand, $actual),
            'membership' => self::matchesMembership($operator, $operand, $actual),
            'string'     => self::matchesString($operator, $operand, $actual),
            'number'     => self::matchesNumericComparison($operator, $operand, $actual),
            'time'       => self::matchesTimeComparison($operator, $operand, $actual),
            'ip'         => self::matchesIp($operator, $operand, $actual),
            'values'     => self::matchesValues($operator, $operand, $actual),
        };
    }

    /**
     * Report an unknown operator as invalid.
     *
     * @param  string  $operator
     * @return \SineMacula\Laravel\Authorization\Evaluation\MatchResult
     */
    private static function unknownOperator(string $operator): MatchResult
    {
        self::logUnknownOperator($operator);

        return MatchResult::invalid("unknown operator '{$operator}'");
    }

    /**
     * Describe an operand of the wrong type for its operator.
     *
     * @param  string  $operator
     * @return string
     */
    private static function invalidOperand(string $operator): string
    {
        return "invalid operand for operator '{$operator}'";
    }

    /**
     * Evaluate `eq` and `neq`, which compare one scalar strictly. A value that
     * is neither a scalar nor null is undecidable, so `neq` never holds for a
     * list or a map.
     *
     * @param  string  $operator
     * @param  mixed  $operand
     * @param  mixed  $actual
     * @return \SineMacula\Laravel\Authorization\Evaluation\MatchResult
     */
    private static function matchesEquality(string $operator, mixed $operand, mixed $actual): MatchResult
    {
        if (!\is_scalar($operand)) {
            return MatchResult::invalid(self::invalidOperand($operator));
        }

        if (!self::isComparable($actual)) {
            return MatchResult::undecidable("operator '{$operator}' needs a scalar");
        }

        return MatchResult::fromBool(($actual === $operand) === ($operator === 'eq'));
    }

    /**
     * Evaluate `in` and `not_in`, which compare the value strictly with each
     * member of a set.
     *
     * @param  string  $operator
     * @param  mixed  $operand
     * @param  mixed  $actual
     * @return \SineMacula\Laravel\Authorization\Evaluation\MatchResult
     */
    private static function matchesMembership(string $operator, mixed $operand, mixed $actual): MatchResult
    {
        if (!ConditionOperands::isScalarSet($operand)) {
            return MatchResult::invalid(self::invalidOperand($operator));
        }

        if (!self::isComparable($actual)) {
            return MatchResult::undecidable("operator '{$operator}' needs a scalar");
        }

        return MatchResult::fromBool(\in_array($actual, $operand, true) === ($operator === 'in'));
    }

    /**
     * Determine whether a context value can be compared by the equality and
     * membership operators: a scalar, or null, which equals no operand.
     *
     * @param  mixed  $actual
     * @return bool
     */
    private static function isComparable(mixed $actual): bool
    {
        return $actual === null || \is_scalar($actual);
    }

    /**
     * Evaluate the string operators. A pattern operand reaches here already
     * prepared for `fnmatch()` without `FNM_NOESCAPE`. A value or substituted
     * operand holding a NUL byte is undecidable, since `fnmatch()` cannot test
     * it and the three operators are kept alike.
     *
     * @param  string  $operator
     * @param  mixed  $operand
     * @param  mixed  $actual
     * @return \SineMacula\Laravel\Authorization\Evaluation\MatchResult
     */
    private static function matchesString(string $operator, mixed $operand, mixed $actual): MatchResult
    {
        if (!\is_string($operand)) {
            return MatchResult::invalid(self::invalidOperand($operator));
        }

        if ($operand === '' || !\is_string($actual) || \str_contains($operand . $actual, "\0")) {
            return MatchResult::undecidable(match (true) {
                $operand === ''      => "operator '{$operator}' has an empty operand",
                !\is_string($actual) => "operator '{$operator}' needs a string value",
                default              => "operator '{$operator}' cannot test a NUL byte",
            });
        }

        return MatchResult::fromBool(match ($operator) {
            'starts_with' => \str_starts_with($actual, $operand),
            'ends_with'   => \str_ends_with($actual, $operand),
            default       => \fnmatch($operand, $actual),
        });
    }

    /**
     * Evaluate `gt`, `gte`, `lt` and `lte`.
     *
     * @param  string  $operator
     * @param  mixed  $operand
     * @param  mixed  $actual
     * @return \SineMacula\Laravel\Authorization\Evaluation\MatchResult
     */
    private static function matchesNumericComparison(string $operator, mixed $operand, mixed $actual): MatchResult
    {
        if (!ConditionOperands::isNumber($operand) || !ConditionOperands::isNumber($actual)) {
            return ConditionOperands::isNumber($operand)
                ? MatchResult::undecidable("operator '{$operator}' needs a number")
                : MatchResult::invalid(self::invalidOperand($operator));
        }

        $left  = (float) $actual;
        $right = (float) $operand;

        return MatchResult::fromBool(match ($operator) {
            'gt'    => $left > $right,
            'gte'   => $left >= $right,
            'lt'    => $left < $right,
            default => $left <= $right,
        });
    }

    /**
     * Evaluate `before` and `after`.
     *
     * @param  string  $operator
     * @param  mixed  $operand
     * @param  mixed  $actual
     * @return \SineMacula\Laravel\Authorization\Evaluation\MatchResult
     */
    private static function matchesTimeComparison(string $operator, mixed $operand, mixed $actual): MatchResult
    {
        $right = ConditionOperands::toTimestamp($operand);
        $left  = ConditionOperands::toTimestamp($actual);

        if ($right === null || $left === null) {
            return $right === null
                ? MatchResult::invalid(self::invalidOperand($operator))
                : MatchResult::undecidable("operator '{$operator}' needs a time");
        }

        return MatchResult::fromBool($operator === 'before' ? $left < $right : $left > $right);
    }

    /**
     * Evaluate the `between` operator, inclusive of both bounds.
     *
     * @param  mixed  $operand
     * @param  mixed  $actual
     * @return \SineMacula\Laravel\Authorization\Evaluation\MatchResult
     */
    private static function matchesBetween(mixed $operand, mixed $actual): MatchResult
    {
        $left = ConditionOperands::toTimestamp($actual);

        if (!ConditionOperands::isTimeRange($operand) || $left === null) {
            return ConditionOperands::isTimeRange($operand)
                ? MatchResult::undecidable('operator \'between\' needs a time')
                : MatchResult::invalid(self::invalidOperand('between'));
        }

        return MatchResult::fromBool($left >= (int) ConditionOperands::toTimestamp($operand[0]) && $left <= (int) ConditionOperands::toTimestamp($operand[1]));
    }

    /**
     * Evaluate the `bool` operator. Both sides must be in a boolean form.
     *
     * @param  mixed  $operand
     * @param  mixed  $actual
     * @return \SineMacula\Laravel\Authorization\Evaluation\MatchResult
     */
    private static function matchesBool(mixed $operand, mixed $actual): MatchResult
    {
        if (!ConditionOperands::isBooleanForm($operand) || !ConditionOperands::isBooleanForm($actual)) {
            return ConditionOperands::isBooleanForm($operand)
                ? MatchResult::undecidable('operator \'bool\' needs a boolean')
                : MatchResult::invalid(self::invalidOperand('bool'));
        }

        return MatchResult::fromBool(ConditionOperands::isTrue($actual) === ConditionOperands::isTrue($operand));
    }

    /**
     * Evaluate the `null` operator for a key the context carries: `true` holds
     * when its value is null, `false` when it is not. A key the context lacks
     * is decided by the statement, before any operator is evaluated.
     *
     * @param  mixed  $operand
     * @param  mixed  $actual
     * @return \SineMacula\Laravel\Authorization\Evaluation\MatchResult
     */
    private static function matchesNull(mixed $operand, mixed $actual): MatchResult
    {
        if (!\is_bool($operand)) {
            return MatchResult::invalid(self::invalidOperand('null'));
        }

        return MatchResult::fromBool(($actual === null) === $operand);
    }

    /**
     * Evaluate `ip_in` and `ip_not_in`. The value must be an IPv4 or IPv6
     * address: `ip_in` holds when it is within any of the ranges and
     * `ip_not_in` when it is within none. A value that is not an address,
     * including one with a zone id or a NUL byte, is undecidable for both, so
     * `ip_not_in` never reads it as outside.
     *
     * @param  string  $operator
     * @param  mixed  $operand
     * @param  mixed  $actual
     * @return \SineMacula\Laravel\Authorization\Evaluation\MatchResult
     */
    private static function matchesIp(string $operator, mixed $operand, mixed $actual): MatchResult
    {
        $ranges  = IpRanges::parse($operand);
        $address = IpRanges::pack($actual);

        if ($ranges === null || $address === null) {
            return $ranges === null
                ? MatchResult::invalid(self::invalidOperand($operator))
                : MatchResult::undecidable("operator '{$operator}' needs an IP address");
        }

        return MatchResult::fromBool(IpRanges::contains($ranges, $address) === ($operator === 'ip_in'));
    }

    /**
     * Evaluate `any_value_in` and `all_values_in`. The value must be a list of
     * scalars: `any_value_in` holds when some element is in the set, and
     * `all_values_in` when the list is not empty and every element is in it.
     *
     * @param  string  $operator
     * @param  mixed  $operand
     * @param  mixed  $actual
     * @return \SineMacula\Laravel\Authorization\Evaluation\MatchResult
     */
    private static function matchesValues(string $operator, mixed $operand, mixed $actual): MatchResult
    {
        if (!ConditionOperands::isScalarSet($operand) || !ConditionOperands::isScalarList($actual)) {
            return ConditionOperands::isScalarSet($operand)
                ? MatchResult::undecidable("operator '{$operator}' needs a list of values")
                : MatchResult::invalid(self::invalidOperand($operator));
        }

        $members = \array_filter($actual, static fn (mixed $element): bool => \in_array($element, $operand, true));

        return MatchResult::fromBool($operator === 'any_value_in'
            ? $members !== []
            : $actual  !== [] && \count($members) === \count($actual));
    }
}
