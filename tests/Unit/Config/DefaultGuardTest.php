<?php

declare(strict_types = 1);

namespace Tests\Unit\Config;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Config\ConfigValue;
use SineMacula\Laravel\Authorization\Config\DefaultGuard;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;

/**
 * Unit tests for reading the default guard at run time: a guard left out is
 * `web`, and a guard or block changed to one that cannot name a guard is
 * refused, never read as `web`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DefaultGuard::class)]
#[CoversClass(ConfigValue::class)]
final class DefaultGuardTest extends TestCase
{
    /**
     * A configured guard is read as it is.
     *
     * @return void
     */
    public function testAConfiguredGuardIsRead(): void
    {
        self::assertSame('api', DefaultGuard::get(new Repository(['authorization' => ['defaults' => ['guard' => 'api']]])));
    }

    /**
     * A guard the configuration leaves out, or a configuration without the
     * block or the authorization config, is `web`.
     *
     * @return void
     */
    public function testAGuardLeftOutIsWeb(): void
    {
        self::assertSame('web', DefaultGuard::get(new Repository(['authorization' => ['defaults' => []]])));
        self::assertSame('web', DefaultGuard::get(new Repository(['authorization' => []])));
        self::assertSame('web', DefaultGuard::get(new Repository));
    }

    /**
     * Return each configuration refused, with the path it is refused under and
     * why.
     *
     * @return iterable<string, array{array<string, mixed>, string, string}>
     */
    public static function refusedConfigs(): iterable
    {
        yield 'a null guard' => [['defaults' => ['guard' => null]], 'authorization.defaults.guard', 'expected a non-empty name, got \'null\' (null).'];
        yield 'an empty guard' => [['defaults' => ['guard' => '']], 'authorization.defaults.guard', 'expected a non-empty name, got \'\' (string).'];
        yield 'an int guard' => [['defaults' => ['guard' => 5]], 'authorization.defaults.guard', 'expected a non-empty name, got 5 (int).'];
        yield 'a null block' => [['defaults' => null], 'authorization.defaults', 'expected an array, got \'null\' (null).'];
        yield 'a string block' => [['defaults' => 'web'], 'authorization.defaults', 'expected an array, got \'web\' (string).'];
    }

    /**
     * A guard, or the block holding it, that cannot name a guard is refused
     * under its own path, never read as `web`.
     *
     * @param  array<string, mixed>  $authorization
     * @param  string  $key
     * @param  string  $reason
     * @return void
     */
    #[DataProvider('refusedConfigs')]
    public function testAGuardThatCannotNameAGuardIsRefused(array $authorization, string $key, string $reason): void
    {
        try {
            DefaultGuard::get(new Repository(['authorization' => $authorization]));

            self::fail('InvalidAuthorizationConfigException was not thrown.');
        } catch (InvalidAuthorizationConfigException $exception) {
            self::assertSame($key, $exception->getConfigKey());
            self::assertSame($reason, $exception->getReason());
        }
    }
}
