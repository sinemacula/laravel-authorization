<?php

declare(strict_types = 1);

namespace Tests\Unit\Config;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Config\IntegerSetting;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;
use Tests\Concerns\ReadsRefusedSettings;

/**
 * Unit tests for reading a whole-number setting as it is written (N117).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IntegerSetting::class)]
final class IntegerSettingTest extends TestCase
{
    use ReadsRefusedSettings;

    /**
     * Return each value holding a whole number, with the number it holds.
     *
     * @return iterable<string, array{mixed, int}>
     */
    public static function wholeNumbers(): iterable
    {
        yield 'an int' => [300, 300];
        yield 'zero' => [0, 0];
        yield 'a negative int' => [-5, -5];
        yield 'the largest int' => [\PHP_INT_MAX, \PHP_INT_MAX];
        yield 'the smallest int' => [\PHP_INT_MIN, \PHP_INT_MIN];
        yield 'a string the environment gives' => ['300', 300];
        yield 'a string of zero' => ['0', 0];
        yield 'a negative string' => ['-5', -5];
        yield 'a string of one digit' => ['7', 7];
        yield 'the largest int as a string' => [(string) \PHP_INT_MAX, \PHP_INT_MAX];
        yield 'the smallest int as a string' => [(string) \PHP_INT_MIN, \PHP_INT_MIN];
    }

    /**
     * An int is taken as it is, and a string written as a whole number in base
     * 10 the plain way is read as that number.
     *
     * @param  mixed  $value
     * @param  int  $integer
     * @return void
     */
    #[DataProvider('wholeNumbers')]
    public function testAWholeNumberIsRead(mixed $value, int $integer): void
    {
        self::assertSame($integer, IntegerSetting::of($value));
        self::assertSame($integer, IntegerSetting::require('authorization.example', $value, \PHP_INT_MIN));
    }

    /**
     * Return each value holding no whole number.
     *
     * @return iterable<string, array{mixed}>
     */
    public static function notWholeNumbers(): iterable
    {
        yield 'trailing letters' => ['12abc'];
        yield 'an exponent' => ['1e3'];
        yield 'a leading space' => [' 5'];
        yield 'a trailing space' => ['5 '];
        yield 'a trailing newline' => ["5\n"];
        yield 'a decimal' => ['5.0'];
        yield 'an empty string' => [''];
        yield 'a minus zero' => ['-0'];
        yield 'a leading zero' => ['007'];
        yield 'a plus sign' => ['+5'];
        yield 'a hexadecimal number' => ['0x1A'];
        yield 'an underscore' => ['1_000'];
        yield 'a minus sign alone' => ['-'];
        yield 'a number too large' => ['9223372036854775808'];
        yield 'a number too small' => ['-9223372036854775809'];
        yield 'a float' => [5.0];
        yield 'true' => [true];
        yield 'false' => [false];
        yield 'null' => [null];
        yield 'an array' => [[5]];
        yield 'an object' => [new \stdClass];
    }

    /**
     * Anything else holds no whole number.
     *
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('notWholeNumbers')]
    public function testAnythingElseHoldsNone(mixed $value): void
    {
        self::assertNull(IntegerSetting::of($value));
    }

    /**
     * A value holding no whole number, or one below the least allowed, is
     * refused under the setting's path, saying what was expected and what it
     * got; the least allowed itself is accepted.
     *
     * @return void
     */
    public function testRequireRefusesUnderThePath(): void
    {
        self::assertSame(1, IntegerSetting::require('authorization.example', '1', 1));
        self::assertSame(60, IntegerSetting::require('authorization.example', 60, 60));

        $refusals = [
            ['0', 1, 'a whole number', 'expected a whole number of at least 1, got \'0\' (string).'],
            [59, 60, 'a whole number', 'expected a whole number of at least 60, got 59 (int).'],
            ['1e3', 1, 'a whole number', 'expected a whole number of at least 1, got \'1e3\' (string).'],
            [null, 1, 'a whole number of seconds', 'expected a whole number of seconds of at least 1, got \'null\' (null).'],
        ];

        foreach ($refusals as [$value, $least, $expected, $reason]) {
            try {
                IntegerSetting::require('authorization.example', $value, $least, $expected);

                self::fail('The value was accepted.');
            } catch (InvalidAuthorizationConfigException $exception) {
                self::assertSame('authorization.example', $exception->getConfigKey());
                self::assertSame($reason, $exception->getReason());
            }
        }
    }

    /**
     * A value that is not a whole number is refused as of the wrong type, and
     * one below the least allowed as out of range.
     *
     * @return void
     */
    public function testATypeIsToldFromARange(): void
    {
        self::assertSame(
            ['authorization.x', 'invalid_type', 'a whole number of at least 1', 'string'],
            self::refusedSetting(static fn (): int => IntegerSetting::require('authorization.x', '1.5', 1)),
        );
        self::assertSame(
            ['authorization.x', 'out_of_range', 'a whole number of at least 1', 'int'],
            self::refusedSetting(static fn (): int => IntegerSetting::require('authorization.x', 0, 1)),
        );
    }
}
