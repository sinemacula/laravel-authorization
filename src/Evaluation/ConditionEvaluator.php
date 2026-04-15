<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

/**
 * Internal helper responsible for evaluating the condition operators
 * supported by the policy statement.
 *
 * The helper keeps the statement class within its complexity budget by
 * lifting the CIDR, time and unknown-operator fallbacks into small,
 * single-purpose static methods. It is not part of the public API.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ConditionEvaluator
{
    /**
     * Determine whether the supplied IPv4 address falls within the
     * supplied CIDR range.
     *
     * @param  string  $ip
     * @param  string  $cidr
     * @return bool
     */
    public static function matchesCidr(string $ip, string $cidr): bool
    {
        if (!\str_contains($cidr, '/')) {
            return $ip === $cidr;
        }

        [$subnet, $bits] = \explode('/', $cidr, 2);

        $bitsInt    = self::parseCidrBits($bits);
        $ipLong     = \ip2long($ip);
        $subnetLong = \ip2long($subnet);

        if ($bitsInt === null || $ipLong === false || $subnetLong === false) {
            return false;
        }

        $mask = $bitsInt === 0 ? 0 : (-1 << (32 - $bitsInt));

        return ($ipLong & $mask) === ($subnetLong & $mask);
    }

    /**
     * Compare two time-like values using the supplied comparator.
     *
     * @param  mixed  $actual
     * @param  mixed  $operand
     * @param  string  $comparator
     * @return bool
     */
    public static function compareTimes(mixed $actual, mixed $operand, string $comparator): bool
    {
        $left  = self::toTimestamp($actual);
        $right = self::toTimestamp($operand);

        if ($left === null || $right === null) {
            return false;
        }

        return match ($comparator) {
            '<'     => $left < $right,
            '>'     => $left > $right,
            default => false,
        };
    }

    /**
     * Evaluate the `between` operator.
     *
     * @param  mixed  $actual
     * @param  mixed  $operand
     * @return bool
     */
    public static function matchesBetween(mixed $actual, mixed $operand): bool
    {
        if (!\is_array($operand) || !\array_key_exists(0, $operand) || !\array_key_exists(1, $operand)) {
            return false;
        }

        $left  = self::toTimestamp($actual);
        $lower = self::toTimestamp($operand[0]);
        $upper = self::toTimestamp($operand[1]);

        if ($left === null || $lower === null || $upper === null) {
            return false;
        }

        return $left >= $lower && $left <= $upper;
    }

    /**
     * Log an unknown-operator warning and return false.
     *
     * The call is wrapped in a try/catch so the evaluator remains
     * usable in pure-PHP contexts such as benchmarks.
     *
     * @param  string  $operator
     * @return bool
     */
    public static function logUnknownOperator(string $operator): bool
    {
        if (\function_exists('logger')) {
            try {
                // @phpstan-ignore-next-line function.notFound
                logger()->debug("Unknown authorization condition operator '{$operator}' — evaluated to false.");
            } catch (\Throwable) {
                // Silently ignore logger failures.
            }
        }

        return false;
    }

    /**
     * Parse and validate the prefix-length portion of a CIDR range.
     *
     * @param  string  $bits
     * @return int|null
     */
    private static function parseCidrBits(string $bits): ?int
    {
        if ($bits === '' || !\ctype_digit($bits)) {
            return null;
        }

        $value = (int) $bits;

        return $value > 32 ? null : $value;
    }

    /**
     * Coerce a scalar value into a UNIX timestamp, returning null when
     * the value cannot be parsed.
     *
     * @param  mixed  $value
     * @return int|null
     */
    private static function toTimestamp(mixed $value): ?int
    {
        if (\is_int($value)) {
            return $value;
        }

        if (!\is_string($value) || $value === '') {
            return null;
        }

        $timestamp = self::parseDateString($value);

        return $timestamp === false ? null : $timestamp;
    }

    /**
     * Safely invoke PHP's `strtotime()`, catching any parser throwables.
     *
     * @param  string  $value
     * @return false|int
     */
    private static function parseDateString(string $value): false|int
    {
        try {
            return \strtotime($value);
        } catch (\Throwable) {
            return false;
        }
    }
}
