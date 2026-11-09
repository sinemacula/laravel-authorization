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
     * Every setting is optional, and each accepts its least value.
     *
     * @return void
     */
    public function testEverySettingIsOptional(): void
    {
        UsageConfigValidator::validate([]);
        UsageConfigValidator::validate(['enabled' => false, 'interval' => 60, 'batch' => 1, 'retention' => 1, 'connection' => null, 'queue' => 'usage']);

        self::assertSame(60, UsageConfigValidator::whole('interval', 60));
        self::assertSame(1, UsageConfigValidator::whole('unknown', 1));
        self::assertNull(UsageConfigValidator::name('queue', null));
        self::assertTrue(UsageConfigValidator::enabled(true));
    }

    /**
     * Return blocks the check refuses, each with the key and message it names.
     *
     * @return iterable<string, array{mixed, string, string}>
     */
    public static function refused(): iterable
    {
        yield 'not an array' => ['on', 'authorization.usage', 'expected an array of settings, got "on" (string).'];
        yield 'an unknown setting' => [
            ['enable' => true],
            'authorization.usage',
            'unknown setting \'enable\'; expected one of enabled, interval, batch, connection, queue, retention.',
        ];
        yield 'enabled that is no boolean' => [['enabled' => 1], 'authorization.usage.enabled', 'expected a boolean, got 1 (int).'];
        yield 'an interval under a minute' => [['interval' => 59], 'authorization.usage.interval', 'expected a whole number of at least 60, got 59 (int).'];
        yield 'an interval that is no number' => [['interval' => '3600'], 'authorization.usage.interval', 'expected a whole number of at least 60, got "3600" (string).'];
        yield 'an empty batch' => [['batch' => 0], 'authorization.usage.batch', 'expected a whole number of at least 1, got 0 (int).'];
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
