<?php

declare(strict_types = 1);

namespace Tests\Unit\Evaluation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\IpRanges;

/**
 * Unit tests for the address ranges of the `ip_in` and `ip_not_in` operators.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(IpRanges::class)]
final class IpRangesTest extends TestCase
{
    /**
     * Provide operands with the ranges they parse into.
     *
     * @return iterable<string, array{0: mixed, 1: list<array{0: string, 1: int}>}>
     */
    public static function validOperandProvider(): iterable
    {
        yield 'ipv4 range' => ['10.0.0.0/8', [[self::packed('10.0.0.0'), 8]]];
        yield 'ipv4 /0' => ['0.0.0.0/0', [[self::packed('0.0.0.0'), 0]]];
        yield 'ipv4 /32' => ['1.2.3.4/32', [[self::packed('1.2.3.4'), 32]]];
        yield 'ipv4 address' => ['1.2.3.4', [[self::packed('1.2.3.4'), 32]]];
        yield 'ipv6 range' => ['2001:db8::/32', [[self::packed('2001:db8::'), 32]]];
        yield 'ipv6 /128' => ['::1/128', [[self::packed('::1'), 128]]];
        yield 'ipv6 address' => ['::1', [[self::packed('::1'), 128]]];
        yield 'set' => [['10.0.0.0/8', '::1'], [[self::packed('10.0.0.0'), 8], [self::packed('::1'), 128]]];
        yield 'set of one' => [['1.2.3.4'], [[self::packed('1.2.3.4'), 32]]];
    }

    /**
     * parse() reads one address or range, or a list of them, into packed
     * networks and prefix lengths; an address alone is its full length.
     *
     * @param  mixed  $operand
     * @param  list<array{0: string, 1: int}>  $expected
     * @return void
     */
    #[DataProvider('validOperandProvider')]
    public function testParsesValidOperands(mixed $operand, array $expected): void
    {
        self::assertSame($expected, IpRanges::parse($operand));
    }

    /**
     * Provide operands that are not an address, a range or a non-empty list of
     * them.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function invalidOperandProvider(): iterable
    {
        yield 'ipv4 prefix 33' => ['10.0.0.0/33'];
        yield 'ipv6 prefix 129' => ['::1/129'];
        yield 'empty prefix' => ['10.0.0.0/'];
        yield 'non-digit prefix' => ['10.0.0.0/x'];
        yield 'signed prefix' => ['10.0.0.0/+8'];
        yield 'negative prefix' => ['10.0.0.0/-1'];
        yield 'double prefix' => ['10.0.0.0/8/8'];
        yield 'malformed network' => ['bad/8'];
        yield 'malformed address' => ['bad'];
        yield 'empty string' => [''];
        yield 'int' => [167772160];
        yield 'null' => [null];
        yield 'empty list' => [[]];
        yield 'list with a bad range' => [['10.0.0.0/8', 'bad']];
        yield 'list with a bad first range' => [['bad', '10.0.0.0/8']];
        yield 'list with a non-string' => [['10.0.0.0/8', 1]];
        yield 'list with a list' => [[['10.0.0.0/8']]];
        yield 'map' => [['a' => '10.0.0.0/8']];
        yield 'list from one' => [[1 => '10.0.0.0/8']];
    }

    /**
     * parse() returns null for a malformed operand, including a list holding
     * one malformed range.
     *
     * @param  mixed  $operand
     * @return void
     */
    #[DataProvider('invalidOperandProvider')]
    public function testRefusesInvalidOperands(mixed $operand): void
    {
        self::assertNull(IpRanges::parse($operand));
    }

    /**
     * Provide addresses with whether they are within the ranges.
     *
     * @return iterable<string, array{0: mixed, 1: string, 2: bool}>
     */
    public static function containsProvider(): iterable
    {
        yield 'inside /8' => ['10.0.0.0/8', '10.255.255.255', true];
        yield 'outside /8' => ['10.0.0.0/8', '11.0.0.0', false];
        yield 'inside /9 below the boundary' => ['10.0.0.0/9', '10.127.255.255', true];
        yield 'outside /9 at the boundary' => ['10.0.0.0/9', '10.128.0.0', false];
        yield 'inside /7 across a byte' => ['10.0.0.0/7', '11.0.0.0', true];
        yield 'leading bits differ' => ['10.0.0.0/8', '138.0.0.0', false];
        yield 'last bit of /32' => ['1.2.3.4/32', '1.2.3.5', false];
        yield 'exact address' => ['1.2.3.4', '1.2.3.4', true];
        yield 'every ipv4 address' => ['0.0.0.0/0', '255.255.255.255', true];
        yield 'ipv6 inside' => ['2001:db8::/33', '2001:db8:7fff::1', true];
        yield 'ipv6 outside' => ['2001:db8::/33', '2001:db8:8000::', false];
        yield 'other family, ipv4 range' => ['0.0.0.0/0', '::', false];
        yield 'other family, ipv6 range' => ['::/0', '0.0.0.0', false];
        yield 'mapped ipv4 address' => ['10.0.0.0/8', '::ffff:10.0.0.1', false];
        yield 'second range of a set' => [['10.0.0.0/8', '192.168.0.0/16'], '192.168.1.1', true];
        yield 'no range of a set' => [['10.0.0.0/8', '192.168.0.0/16'], '172.16.0.1', false];
        yield 'mixed set, ipv6 address' => [['10.0.0.0/8', '2001:db8::/32'], '2001:db8::1', true];
    }

    /**
     * contains() reports whether the packed address is within any range of its
     * own family.
     *
     * @param  mixed  $operand
     * @param  string  $address
     * @param  bool  $expected
     * @return void
     */
    #[DataProvider('containsProvider')]
    public function testContains(mixed $operand, string $address, bool $expected): void
    {
        $ranges = IpRanges::parse($operand);

        self::assertNotNull($ranges);
        self::assertSame($expected, IpRanges::contains($ranges, self::packed($address)));
    }

    /**
     * No address is within an empty set of ranges.
     *
     * @return void
     */
    public function testNothingIsWithinNoRanges(): void
    {
        self::assertFalse(IpRanges::contains([], self::packed('10.0.0.1')));
    }

    /**
     * Pack an address the test knows to be valid.
     *
     * @param  string  $address
     * @return string
     */
    private static function packed(string $address): string
    {
        $packed = \inet_pton($address);

        self::assertIsString($packed);

        return $packed;
    }
}
