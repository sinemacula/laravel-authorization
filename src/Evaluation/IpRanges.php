<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

/**
 * Internal helper reading the address ranges of the `ip_in` and `ip_not_in`
 * operators and testing an address against them.
 *
 * An operand is one IPv4 or IPv6 address or CIDR range, or a non-empty list of
 * them read as one set of ranges. An address without a prefix length is a range
 * of exactly that address. An address of the other family is within none of a
 * range's addresses, so `::ffff:10.0.0.1` is not within `10.0.0.0/8`. It is not
 * part of the public API.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class IpRanges
{
    /**
     * Parse an operand into its ranges, each a packed network address and a
     * prefix length, or return null when the operand is not one address or
     * range, or a non-empty list of them.
     *
     * @param  mixed  $operand
     * @return list<array{0: string, 1: int}>|null
     */
    public static function parse(mixed $operand): ?array
    {
        if (\is_string($operand)) {
            $range = self::parseRange($operand);

            return $range === null ? null : [$range];
        }

        if (!\is_array($operand) || $operand === [] || !\array_is_list($operand)) {
            return null;
        }

        $strings = \array_filter($operand, \is_string(...));
        $parsed  = \array_filter(\array_map(static fn (string $range): ?array => self::parseRange($range), $strings), static fn (?array $range): bool => $range !== null);

        return \count($parsed) === \count($operand) ? \array_values($parsed) : null;
    }

    /**
     * Determine whether a packed address is within any of the ranges.
     *
     * @param  list<array{0: string, 1: int}>  $ranges
     * @param  string  $address
     * @return bool
     */
    public static function contains(array $ranges, string $address): bool
    {
        foreach ($ranges as [$network, $bits]) {
            if (\strlen($address) === \strlen($network) && self::prefix($address, $bits) === self::prefix($network, $bits)) {
                return true;
            }
        }

        return false;
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
}
