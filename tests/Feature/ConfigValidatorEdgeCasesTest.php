<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Container\Container;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Config\ConfigValidator;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;
use Tests\TestCase;

/**
 * Coverage for `ConfigValidator` branches that reject non-array
 * container keys, empty entries, non-string scalars, and the
 * no-op short-circuit the validator takes when the cache container
 * binding is not present (unit-level embedding). Each test drives
 * the shipped validator through a single misconfiguration that a
 * consumer can realistically set.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(ConfigValidator::class)]
#[CoversClass(InvalidAuthorizationConfigException::class)]
final class ConfigValidatorEdgeCasesTest extends TestCase
{
    /**
     * `permission_enums` must be an array — a scalar is rejected
     * with a typed exception.
     *
     * @return void
     */
    public function testPermissionEnumsMustBeArray(): void
    {
        /** @var \Illuminate\Contracts\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class);
        $config->set('authorization.permission_enums', 'nope');

        $this->expectException(InvalidAuthorizationConfigException::class);
        $this->expectExceptionMessageMatches('/expected an array of enum class names/');

        ConfigValidator::validate((array) $config->get('authorization'), $this->app);
    }

    /**
     * `permission_providers` must be an array — a scalar is rejected
     * with a typed exception.
     *
     * @return void
     */
    public function testPermissionProvidersMustBeArray(): void
    {
        /** @var \Illuminate\Contracts\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class);
        $config->set('authorization.permission_providers', 'nope');

        $this->expectException(InvalidAuthorizationConfigException::class);
        $this->expectExceptionMessageMatches('/expected an array of class names/');

        ConfigValidator::validate((array) $config->get('authorization'), $this->app);
    }

    /**
     * `permission_providers` entries must be non-empty class-strings.
     *
     * @return void
     */
    public function testPermissionProviderEntryMustBeNonEmptyString(): void
    {
        /** @var \Illuminate\Contracts\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class);
        $config->set('authorization.permission_providers', ['']);

        $this->expectException(InvalidAuthorizationConfigException::class);
        $this->expectExceptionMessageMatches('/non-empty class-string/');

        ConfigValidator::validate((array) $config->get('authorization'), $this->app);
    }

    /**
     * `cache.store` must be a string — an integer is rejected by
     * the typed validator before the cache manager is consulted.
     *
     * @return void
     */
    public function testCacheStoreMustBeString(): void
    {
        /** @var \Illuminate\Contracts\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class);
        $config->set('authorization.cache.store', 42);

        $this->expectException(InvalidAuthorizationConfigException::class);
        $this->expectExceptionMessageMatches('/expected a cache-store name string/');

        ConfigValidator::validate((array) $config->get('authorization'), $this->app);
    }

    /**
     * When the container has no `cache` binding the validator
     * short-circuits without raising — library-mode embedding
     * where Laravel's cache manager is never wired up.
     *
     * @return void
     */
    public function testCacheStoreSkippedWhenCacheBindingMissing(): void
    {
        $container = new Container;

        ConfigValidator::validate([
            'principal_resolver' => \SineMacula\Laravel\Authorization\Resolvers\NullPrincipalResolver::class,
            'cache'              => ['store' => 'redis'],
        ], $container);

        self::assertFalse($container->bound('cache'));
    }

    /**
     * `principal_resolver` must be a class-string — a non-string
     * value is rejected before `class_exists` is invoked.
     *
     * @return void
     */
    public function testPrincipalResolverMustBeString(): void
    {
        /** @var \Illuminate\Contracts\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class);
        $config->set('authorization.principal_resolver', 123);

        $this->expectException(InvalidAuthorizationConfigException::class);
        $this->expectExceptionMessageMatches('/expected a class-string/');

        ConfigValidator::validate((array) $config->get('authorization'), $this->app);
    }

    /**
     * The `describe` formatter renders non-scalars as their debug
     * type — reached via a non-scalar `gate.on_conflict` that drops
     * through to the error branch.
     *
     * @return void
     */
    public function testDescribeHandlesNonScalarValues(): void
    {
        /** @var \Illuminate\Contracts\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class);
        $config->set('authorization.gate.on_conflict', new \stdClass);

        try {
            ConfigValidator::validate((array) $config->get('authorization'), $this->app);
            self::fail('Expected InvalidAuthorizationConfigException.');
        } catch (InvalidAuthorizationConfigException $exception) {
            self::assertStringContainsString(\stdClass::class, $exception->getMessage());
        }
    }
}
