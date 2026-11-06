<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

/**
 * Internal helper reading the operands and context values of the condition
 * operators: which literal operand each operator takes, and the scalar, set,
 * number, time and boolean forms both sides are read in.
 *
 * It is not part of the public API.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ConditionOperands
{
    /** @var array<int|string, bool> Values the `bool` operator accepts, by their boolean meaning. */
    private const array BOOLEAN_FORMS = [
        'true'  => true,
        '1'     => true,
        'false' => false,
        '0'     => false,
    ];

    /**
     * Determine whether a literal operand has the type its operator needs. An
     * unknown operator takes no operand.
     *
     * @param  string  $operator
     * @param  mixed  $operand
     * @return bool
     */
    public static function isValid(string $operator, mixed $operand): bool
    {
        $rule = self::rules()[$operator] ?? null;

        return $rule !== null && $rule($operand);
    }

    /**
     * Determine whether the value is a non-empty string: the operand of
     * `starts_with`, `ends_with` and `like`.
     *
     * @param  mixed  $value
     * @return bool
     *
     * @phpstan-assert-if-true non-empty-string $value
     */
    public static function isNonEmptyString(mixed $value): bool
    {
        return \is_string($value) && $value !== '';
    }

    /**
     * Determine whether the value is a non-empty list of scalars: the operand
     * of a set operator.
     *
     * @param  mixed  $value
     * @return bool
     *
     * @phpstan-assert-if-true non-empty-list<scalar> $value
     */
    public static function isScalarSet(mixed $value): bool
    {
        return $value !== [] && self::isScalarList($value);
    }

    /**
     * Determine whether the value is a list of scalars, possibly empty: the
     * context value of `any_value_in` and `all_values_in`.
     *
     * @param  mixed  $value
     * @return bool
     *
     * @phpstan-assert-if-true list<scalar> $value
     */
    public static function isScalarList(mixed $value): bool
    {
        return \is_array($value)
            && \array_is_list($value)
            && \array_filter($value, static fn (mixed $element): bool => !\is_scalar($element)) === [];
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
    public static function isNumber(mixed $value): bool
    {
        return \is_numeric($value) && \is_finite((float) $value);
    }

    /**
     * Determine whether the value is a boolean or one of the forms the `bool`
     * operator accepts: `1`, `0`, `'1'`, `'0'`, `'true'` and `'false'`.
     *
     * @param  mixed  $value
     * @return bool
     */
    public static function isBooleanForm(mixed $value): bool
    {
        return \is_bool($value) || ((\is_int($value) || \is_string($value)) && \array_key_exists((string) $value, self::BOOLEAN_FORMS));
    }

    /**
     * Determine whether a value in an accepted boolean form means true.
     *
     * @param  mixed  $value
     * @return bool
     */
    public static function isTrue(mixed $value): bool
    {
        return $value === true || ((\is_int($value) || \is_string($value)) && (self::BOOLEAN_FORMS[(string) $value] ?? false));
    }

    /**
     * Determine whether the operand is a pair of parseable time bounds.
     *
     * @param  mixed  $operand
     * @return bool
     *
     * @phpstan-assert-if-true array{0: mixed, 1: mixed} $operand
     */
    public static function isTimeRange(mixed $operand): bool
    {
        if (!\is_array($operand) || !\array_key_exists(0, $operand) || !\array_key_exists(1, $operand)) {
            return false;
        }

        return self::toTimestamp($operand[0]) !== null && self::toTimestamp($operand[1]) !== null;
    }

    /**
     * Coerce a time-like value into a UNIX timestamp, returning null when the
     * value cannot be parsed.
     *
     * @param  mixed  $value
     * @return int|null
     */
    public static function toTimestamp(mixed $value): ?int
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
     * Return the rule each operator's literal operand must meet, by operator,
     * built once.
     *
     * @return array<string, \Closure(mixed): bool>
     */
    private static function rules(): array
    {
        static $rules = null;

        $isTime = static fn (mixed $operand): bool => self::toTimestamp($operand) !== null;
        $isIp   = static fn (mixed $operand): bool => IpRanges::parse($operand) !== null;

        return $rules ??= [
            'eq'            => \is_scalar(...),
            'neq'           => \is_scalar(...),
            'in'            => self::isScalarSet(...),
            'not_in'        => self::isScalarSet(...),
            'starts_with'   => self::isNonEmptyString(...),
            'ends_with'     => self::isNonEmptyString(...),
            'like'          => self::isNonEmptyString(...),
            'gt'            => self::isNumber(...),
            'gte'           => self::isNumber(...),
            'lt'            => self::isNumber(...),
            'lte'           => self::isNumber(...),
            'before'        => $isTime,
            'after'         => $isTime,
            'between'       => self::isTimeRange(...),
            'bool'          => self::isBooleanForm(...),
            'null'          => \is_bool(...),
            'ip_in'         => $isIp,
            'ip_not_in'     => $isIp,
            'any_value_in'  => self::isScalarSet(...),
            'all_values_in' => self::isScalarSet(...),
        ];
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
