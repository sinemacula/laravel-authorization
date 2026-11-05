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
 *   unparseable time, a string that is not an IP address) is undecidable;
 * - an operand of the wrong type (`in` without a list, `between` without two
 *   bounds, a malformed range) or an unknown operator is invalid.
 *
 * It is not part of the public API.
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
        'null',
        'not_null',
        'cidr',
        'starts_with',
        'ends_with',
        'string_like',
        'before',
        'after',
        'between',
        'gt',
        'gte',
        'lt',
        'lte',
        'bool',
    ];

    /** @var list<string> Operators whose operand is a glob pattern. */
    public const array PATTERN_OPERATORS = ['string_like'];

    /** @var list<string> Operators whose operand is never interpolated (a list or a pair of bounds). */
    private const array LITERAL_OPERAND_OPERATORS = ['in', 'not_in', 'between'];

    /** @var array<string, string> The family each operator is evaluated by. */
    private const array FAMILIES = [
        'eq'          => 'equality',
        'neq'         => 'equality',
        'in'          => 'equality',
        'not_in'      => 'equality',
        'null'        => 'equality',
        'not_null'    => 'equality',
        'starts_with' => 'string',
        'ends_with'   => 'string',
        'string_like' => 'string',
        'before'      => 'time',
        'after'       => 'time',
        'between'     => 'between',
        'gt'          => 'number',
        'gte'         => 'number',
        'lt'          => 'number',
        'lte'         => 'number',
        'cidr'        => 'cidr',
        'bool'        => 'bool',
    ];

    /** @var array<int|string, bool> Values the `bool` operator accepts, by their boolean meaning. */
    private const array BOOLEAN_FORMS = [
        'true'  => true,
        '1'     => true,
        'false' => false,
        '0'     => false,
    ];

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
        return match (self::FAMILIES[$operator] ?? null) {
            'equality' => self::matchesEquality($operator, $operand, $actual),
            'string'   => self::matchesString($operator, $operand, $actual),
            'time'     => self::matchesTimeComparison($operator, $operand, $actual),
            'between'  => self::matchesBetween($operand, $actual),
            'number'   => self::matchesNumericComparison($operator, $operand, $actual),
            'cidr'     => self::matchesCidr($operand, $actual),
            'bool'     => self::matchesBool($operand, $actual),
            default    => self::unknownOperator($operator),
        };
    }

    /**
     * Validate the literal operand of an operator, as written in a policy
     * document, returning the reason it is invalid or null when it is valid.
     *
     * A string operand containing a `${…}` reference is accepted for the
     * operators that interpolate their operand, since its value is known only
     * at evaluation time. The operands of `in`, `not_in` and `between` are
     * never interpolated, so they are always checked.
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

        $deferred = \is_string($operand) && ContextInterpolator::containsReference($operand) && !\in_array($operator, self::LITERAL_OPERAND_OPERATORS, true);

        return $deferred || self::isValidOperand($operator, $operand) ? null : "invalid operand for operator '{$operator}'";
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
     * Determine whether a literal operand has the type its operator needs.
     *
     * @param  string  $operator
     * @param  mixed  $operand
     * @return bool
     */
    private static function isValidOperand(string $operator, mixed $operand): bool
    {
        return match ($operator) {
            'in', 'not_in'                            => \is_array($operand),
            'cidr'                                    => \is_string($operand) && self::parseRange($operand) !== null,
            'starts_with', 'ends_with', 'string_like' => \is_string($operand) && $operand                   !== '',
            'before', 'after'                         => self::toTimestamp($operand)                        !== null,
            'between'                                 => self::isTimeRange($operand),
            'gt', 'gte', 'lt', 'lte'                  => self::isNumber($operand),
            'bool'                                    => self::isBooleanForm($operand),
            default                                   => true,
        };
    }

    /**
     * Evaluate the equality and membership operators.
     *
     * @param  string  $operator
     * @param  mixed  $operand
     * @param  mixed  $actual
     * @return \SineMacula\Laravel\Authorization\Evaluation\MatchResult
     */
    private static function matchesEquality(string $operator, mixed $operand, mixed $actual): MatchResult
    {
        if (\in_array($operator, ['in', 'not_in'], true) && !\is_array($operand)) {
            return MatchResult::invalid("invalid operand for operator '{$operator}'");
        }

        return MatchResult::fromBool(match ($operator) {
            'eq'     => $actual === $operand,
            'neq'    => $actual !== $operand,
            'in'     => \in_array($actual, $operand, true),
            'not_in' => !\in_array($actual, $operand, true),
            'null'   => $actual === null,
            default  => $actual !== null,
        });
    }

    /**
     * Evaluate the string operators. A pattern operand reaches here already
     * prepared for `fnmatch()` without `FNM_NOESCAPE`.
     *
     * @param  string  $operator
     * @param  mixed  $operand
     * @param  mixed  $actual
     * @return \SineMacula\Laravel\Authorization\Evaluation\MatchResult
     */
    private static function matchesString(string $operator, mixed $operand, mixed $actual): MatchResult
    {
        if (!\is_string($operand)) {
            return MatchResult::invalid("invalid operand for operator '{$operator}'");
        }

        if ($operand === '' || !\is_string($actual)) {
            return MatchResult::undecidable($operand === '' ? "operator '{$operator}' has an empty operand" : "operator '{$operator}' needs a string value");
        }

        return MatchResult::fromBool(match ($operator) {
            'starts_with' => \str_starts_with($actual, $operand),
            'ends_with'   => \str_ends_with($actual, $operand),
            default       => \fnmatch($operand, $actual),
        });
    }

    /**
     * Evaluate the `cidr` operator: the value is an IPv4 or IPv6 address within
     * the range, or equal to the address when the operand has no prefix length.
     * An address of the other family is not within the range.
     *
     * @param  mixed  $operand
     * @param  mixed  $actual
     * @return \SineMacula\Laravel\Authorization\Evaluation\MatchResult
     */
    private static function matchesCidr(mixed $operand, mixed $actual): MatchResult
    {
        $range   = \is_string($operand) ? self::parseRange($operand) : null;
        $address = \is_string($actual) ? \inet_pton($actual) : false;

        if ($range === null || $address === false) {
            return $range === null
                ? MatchResult::invalid('invalid operand for operator \'cidr\'')
                : MatchResult::undecidable('operator \'cidr\' needs an IP address');
        }

        [$network, $bits] = $range;

        return MatchResult::fromBool(
            \strlen($address)                === \strlen($network)
            && self::prefix($address, $bits) === self::prefix($network, $bits),
        );
    }

    /**
     * Parse an address or CIDR range into its packed network and prefix length,
     * or null when it is malformed.
     *
     * @param  string  $range
     * @return array{0: string, 1: int}|null
     */
    private static function parseRange(string $range): ?array
    {
        [$subnet, $bits] = \str_contains($range, '/') ? \explode('/', $range, 2) : [$range, null];

        $network = \inet_pton($subnet);

        if ($network === false) {
            return null;
        }

        $maximum = \strlen($network) * 8;

        if ($bits === null) {
            return [$network, $maximum];
        }

        return \ctype_digit($bits) && (int) $bits <= $maximum ? [$network, (int) $bits] : null;
    }

    /**
     * Return the first `$bits` bits of a packed address as a bit string.
     *
     * @param  string  $packed
     * @param  int  $bits
     * @return string
     */
    private static function prefix(string $packed, int $bits): string
    {
        $binary = '';

        foreach (\str_split($packed) as $byte) {
            $binary .= \str_pad(\decbin(\ord($byte)), 8, '0', \STR_PAD_LEFT);
        }

        return \substr($binary, 0, $bits);
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
        $right = self::toTimestamp($operand);
        $left  = self::toTimestamp($actual);

        if ($right === null || $left === null) {
            return $right === null
                ? MatchResult::invalid("invalid operand for operator '{$operator}'")
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
        $left = self::toTimestamp($actual);

        if (!self::isTimeRange($operand) || $left === null) {
            return self::isTimeRange($operand)
                ? MatchResult::undecidable('operator \'between\' needs a time')
                : MatchResult::invalid('invalid operand for operator \'between\'');
        }

        /** @var array{0: mixed, 1: mixed} $operand */
        return MatchResult::fromBool($left >= (int) self::toTimestamp($operand[0]) && $left <= (int) self::toTimestamp($operand[1]));
    }

    /**
     * Determine whether the operand is a pair of parseable time bounds.
     *
     * @param  mixed  $operand
     * @return bool
     */
    private static function isTimeRange(mixed $operand): bool
    {
        if (!\is_array($operand) || !\array_key_exists(0, $operand) || !\array_key_exists(1, $operand)) {
            return false;
        }

        return self::toTimestamp($operand[0]) !== null && self::toTimestamp($operand[1]) !== null;
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
        if (!self::isNumber($operand) || !self::isNumber($actual)) {
            return self::isNumber($operand)
                ? MatchResult::undecidable("operator '{$operator}' needs a number")
                : MatchResult::invalid("invalid operand for operator '{$operator}'");
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
     * Determine whether the value is a finite number, or a numeric string. NaN
     * and the infinities cannot be compared, so they are not numbers here.
     *
     * @param  mixed  $value
     * @return bool
     *
     * @phpstan-assert-if-true int|float|numeric-string $value
     */
    private static function isNumber(mixed $value): bool
    {
        return \is_numeric($value) && \is_finite((float) $value);
    }

    /**
     * Evaluate the `bool` operator. Both sides must be a boolean, or one of
     * `1`, `0`, `'1'`, `'0'`, `'true'` and `'false'`.
     *
     * @param  mixed  $operand
     * @param  mixed  $actual
     * @return \SineMacula\Laravel\Authorization\Evaluation\MatchResult
     */
    private static function matchesBool(mixed $operand, mixed $actual): MatchResult
    {
        if (!self::isBooleanForm($operand) || !self::isBooleanForm($actual)) {
            return self::isBooleanForm($operand)
                ? MatchResult::undecidable('operator \'bool\' needs a boolean')
                : MatchResult::invalid('invalid operand for operator \'bool\'');
        }

        return MatchResult::fromBool(self::isTrue($actual) === self::isTrue($operand));
    }

    /**
     * Determine whether the value is a boolean or one of the forms the `bool`
     * operator accepts.
     *
     * @param  mixed  $value
     * @return bool
     */
    private static function isBooleanForm(mixed $value): bool
    {
        return \is_bool($value) || ((\is_int($value) || \is_string($value)) && \array_key_exists((string) $value, self::BOOLEAN_FORMS));
    }

    /**
     * Determine whether a value in an accepted boolean form means true.
     *
     * @param  mixed  $value
     * @return bool
     */
    private static function isTrue(mixed $value): bool
    {
        return $value === true || ((\is_int($value) || \is_string($value)) && (self::BOOLEAN_FORMS[(string) $value] ?? false));
    }

    /**
     * Coerce a time-like value into a UNIX timestamp, returning null when the
     * value cannot be parsed.
     *
     * @param  mixed  $value
     * @return int|null
     */
    private static function toTimestamp(mixed $value): ?int
    {
        return match (true) {
            $value instanceof \DateTimeInterface     => $value->getTimestamp(),
            \is_int($value)                          => $value,
            \is_float($value)  && \is_finite($value) => (int) $value,
            \is_string($value) && $value !== ''      => self::parseTime($value),
            default                                  => null,
        };
    }

    /**
     * Parse a time string with `strtotime()`, returning null when it cannot be
     * parsed.
     *
     * @param  string  $value
     * @return int|null
     */
    private static function parseTime(string $value): ?int
    {
        $timestamp = \strtotime($value);

        return $timestamp === false ? null : $timestamp;
    }
}
