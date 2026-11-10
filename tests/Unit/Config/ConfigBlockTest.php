<?php

declare(strict_types = 1);

namespace Tests\Unit\Config;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Config\ConfigBlock;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;

/**
 * Unit tests for reading a block of the authorization config whose keys the
 * package defines (N116).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConfigBlock::class)]
final class ConfigBlockTest extends TestCase
{
    /**
     * A block setting only keys the package defines, some or none of them, is
     * returned as it is.
     *
     * @return void
     */
    public function testABlockOfKnownKeysIsReturned(): void
    {
        self::assertSame([], ConfigBlock::of('authorization.example', [], ['one', 'two']));
        self::assertSame(['two' => 2], ConfigBlock::of('authorization.example', ['two' => 2], ['one', 'two']));
        self::assertSame(['one' => null, 'two' => 2], ConfigBlock::of('authorization.example', ['one' => null, 'two' => 2], ['one', 'two']));
    }

    /**
     * Return each block refused, with the path it is refused under and why.
     *
     * @return iterable<string, array{mixed, string, string}>
     */
    public static function refusedBlocks(): iterable
    {
        $expected = 'expected one of one, two.';

        yield 'null' => [null, 'authorization.example', 'expected an array, got \'null\' (null).'];
        yield 'a string' => ['one', 'authorization.example', 'expected an array, got \'one\' (string).'];
        yield 'an int' => [1, 'authorization.example', 'expected an array, got 1 (int).'];
        yield 'an object' => [new \stdClass, 'authorization.example', 'expected an array, got \'stdClass\' (stdClass).'];
        yield 'an unknown key' => [['tow' => 2], 'authorization.example.tow', "unknown key 'tow'; {$expected}"];
        yield 'an unknown key after a known one' => [['one' => 1, 'tow' => 2], 'authorization.example.tow', "unknown key 'tow'; {$expected}"];
        yield 'a key in another case' => [['One' => 1], 'authorization.example.One', "unknown key 'One'; {$expected}"];
        yield 'a list' => [[1], 'authorization.example.0', "unknown key '0'; {$expected}"];
    }

    /**
     * A value that is not an array, or that sets a key the package does not
     * define, is refused under the full path.
     *
     * @param  mixed  $value
     * @param  string  $path
     * @param  string  $reason
     * @return void
     */
    #[DataProvider('refusedBlocks')]
    public function testAMalformedBlockIsRefused(mixed $value, string $path, string $reason): void
    {
        try {
            ConfigBlock::of('authorization.example', $value, ['one', 'two']);

            self::fail('The block was accepted.');
        } catch (InvalidAuthorizationConfigException $exception) {
            self::assertSame($path, $exception->getConfigKey());
            self::assertSame($reason, $exception->getReason());
        }
    }

    /**
     * A key left out takes the default, and a key set, to null included, is
     * returned as it is.
     *
     * @return void
     */
    public function testAnEntryLeftOutTakesTheDefault(): void
    {
        self::assertSame('default', ConfigBlock::entry([], 'one', 'default'));
        self::assertNull(ConfigBlock::entry(['one' => null], 'one', 'default'));
        self::assertSame(0, ConfigBlock::entry(['one' => 0], 'one', 'default'));
        self::assertFalse(ConfigBlock::entry(['one' => false], 'one', true));
    }
}
