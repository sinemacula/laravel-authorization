<?php

declare(strict_types = 1);

namespace Tests\Feature\Usage;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\Config\ConfigValidator;
use SineMacula\Laravel\Authorization\Config\UsageConfigValidator;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;
use Tests\TestCase;

/**
 * Feature tests for the boot-time check of `authorization.usage`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(UsageConfigValidator::class)]
final class UsageConfigValidatorTest extends TestCase
{
    /**
     * Every setting is optional, each accepts its least value, and a whole
     * number is accepted as the environment gives one too.
     *
     * @return void
     */
    public function testEverySettingIsOptional(): void
    {
        UsageConfigValidator::validate([]);
        UsageConfigValidator::validate(['enabled' => false, 'interval' => 60, 'batch' => 1, 'retention' => 1, 'connection' => null, 'queue' => 'usage']);

        self::assertSame(60, UsageConfigValidator::whole('interval', 60));
        self::assertSame(1, UsageConfigValidator::whole('batch', 1));
        self::assertSame(1, UsageConfigValidator::whole('retention', 1));
        self::assertNull(UsageConfigValidator::name('queue', null));
        self::assertTrue(UsageConfigValidator::enabled(true));
        self::assertSame(3600, UsageConfigValidator::whole('interval', '3600'));
        self::assertSame(250, UsageConfigValidator::whole('batch', '250'));
        UsageConfigValidator::validate(['interval' => '60', 'batch' => '1', 'retention' => '400']);
    }

    /**
     * Return blocks the check refuses, each with the key and message it names.
     *
     * @return iterable<string, array{mixed, string, string}>
     */
    public static function refused(): iterable
    {
        yield 'not an array' => ['on', 'authorization.usage', 'expected an array, got \'on\' (string).'];
        yield 'null' => [null, 'authorization.usage', 'expected an array, got \'null\' (null).'];
        yield 'an unknown setting' => [
            ['enable' => true],
            'authorization.usage.enable',
            'unknown key \'enable\'; expected one of enabled, interval, batch, connection, queue, retention.',
        ];
        yield 'an unknown setting after a known one' => [
            ['enabled' => true, 'enable' => 1],
            'authorization.usage.enable',
            'unknown key \'enable\'; expected one of enabled, interval, batch, connection, queue, retention.',
        ];
        yield 'enabled as a string of 0' => [['enabled' => '0'], 'authorization.usage.enabled', 'expected a boolean, got "0" (string).'];
        yield 'enabled as off' => [['enabled' => 'off'], 'authorization.usage.enabled', 'expected a boolean, got "off" (string).'];
        yield 'enabled as null' => [['enabled' => null], 'authorization.usage.enabled', 'expected a boolean, got null (null).'];
        yield 'enabled that is no boolean' => [['enabled' => 1], 'authorization.usage.enabled', 'expected a boolean, got 1 (int).'];
        yield 'an interval under a minute' => [['interval' => 59], 'authorization.usage.interval', 'expected a whole number of at least 60, got 59 (int).'];
        yield 'an interval that is no whole number' => [['interval' => '12abc'], 'authorization.usage.interval', 'expected a whole number of at least 60, got "12abc" (string).'];
        yield 'an interval as an exponent' => [['interval' => '1e3'], 'authorization.usage.interval', 'expected a whole number of at least 60, got "1e3" (string).'];
        yield 'an interval padded' => [['interval' => ' 3600'], 'authorization.usage.interval', 'expected a whole number of at least 60, got " 3600" (string).'];
        yield 'an interval under a minute as a string' => [['interval' => '59'], 'authorization.usage.interval', 'expected a whole number of at least 60, got "59" (string).'];
        yield 'an empty interval' => [['interval' => ''], 'authorization.usage.interval', 'expected a whole number of at least 60, got "" (string).'];
        yield 'an empty batch' => [['batch' => 0], 'authorization.usage.batch', 'expected a whole number of at least 1, got 0 (int).'];
        yield 'an interval with a slash' => [['interval' => 'a/b'], 'authorization.usage.interval', 'expected a whole number of at least 60, got "a/b" (string).'];
        yield 'an interval of invalid text' => [['interval' => "\xB1"], 'authorization.usage.interval', 'expected a whole number of at least 60, got "\ufffd" (string).'];
        yield 'no days kept' => [['retention' => 0], 'authorization.usage.retention', 'expected a whole number of at least 1, got 0 (int).'];
        yield 'no retention' => [['retention' => null], 'authorization.usage.retention', 'expected a whole number of at least 1, got null (null).'];
        yield 'an empty connection' => [['connection' => ''], 'authorization.usage.connection', 'expected a non-empty string or null, got "" (string).'];
        yield 'a queue that is no string' => [['queue' => ['usage']], 'authorization.usage.queue', 'expected a non-empty string or null, got array (array).'];
    }

    /**
     * A malformed block is refused under its key, and the package's check
     * reaches it.
     *
     * @param  mixed  $config
     * @param  string  $key
     * @param  string  $message
     * @return void
     *
     * @throws \LogicException
     */
    #[DataProvider('refused')]
    public function testAMalformedBlockIsRefused(mixed $config, string $key, string $message): void
    {
        try {
            /** @var array<string, mixed> $base */
            $base = config('authorization');

            ConfigValidator::validate([...$base, 'usage' => $config], $this->app ?? throw new \LogicException('No application.'));
            self::fail('A malformed usage block was accepted.');
        } catch (InvalidAuthorizationConfigException $exception) {
            self::assertStringContainsString($key, $exception->getMessage());
            self::assertStringContainsString($message, $exception->getMessage());
        }
    }
}
