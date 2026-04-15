<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Config\ConfigValidator;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;
use SineMacula\Laravel\Authorization\Resolvers\NullPrincipalResolver;
use stdClass;
use Tests\Feature\Stubs\PermissionEnum;
use Tests\TestCase;

/**
 * Feature coverage for the boot-time config validator.
 *
 * Every supported key gets a rejection case (type mismatch,
 * missing class, wrong contract, unknown cache store) and a
 * happy-path case so the defaults keep passing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConfigValidator::class)]
#[CoversClass(InvalidAuthorizationConfigException::class)]
#[CoversClass(AuthorizationServiceProvider::class)]
final class ConfigValidationTest extends TestCase
{
    /**
     * The shipped defaults pass validation end-to-end — booting
     * the provider with the merged config must not throw.
     *
     * @return void
     */
    public function testDefaultConfigPassesValidation(): void
    {
        /** @var \Illuminate\Contracts\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class);

        (new AuthorizationServiceProvider($this->app))->boot();

        self::assertNotNull($config->get('authorization'));
    }

    /**
     * A known-good permission enum passes validation.
     *
     * @return void
     */
    public function testValidPermissionEnumPasses(): void
    {
        /** @var \Illuminate\Contracts\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class);
        $config->set('authorization.permission_enums', [PermissionEnum::class]);

        ConfigValidator::validate((array) $config->get('authorization'), $this->app);

        self::assertTrue(true);
    }

    /**
     * `gate.on_conflict` outside the three sentinels is rejected
     * with a pointer to the offending key.
     *
     * @return void
     */
    public function testInvalidGateOnConflictIsRejected(): void
    {
        /** @var \Illuminate\Contracts\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class);
        $config->set('authorization.gate.on_conflict', 'explode');

        try {
            ConfigValidator::validate((array) $config->get('authorization'), $this->app);
            self::fail('Expected InvalidAuthorizationConfigException was not thrown.');
        } catch (InvalidAuthorizationConfigException $exception) {
            self::assertSame('authorization.gate.on_conflict', $exception->getConfigKey());
            self::assertStringContainsString("'explode'", $exception->getReason());
        }
    }

    /**
     * A `permission_enums` entry that does not resolve to a class
     * is rejected with a concrete error.
     *
     * @return void
     */
    public function testPermissionEnumMissingClassIsRejected(): void
    {
        /** @var \Illuminate\Contracts\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class);
        $config->set('authorization.permission_enums', ['App\\Does\\Not\\Exist']);

        try {
            ConfigValidator::validate((array) $config->get('authorization'), $this->app);
            self::fail('Expected InvalidAuthorizationConfigException was not thrown.');
        } catch (InvalidAuthorizationConfigException $exception) {
            self::assertSame('authorization.permission_enums.0', $exception->getConfigKey());
            self::assertStringContainsString('does not exist', $exception->getReason());
        }
    }

    /**
     * A `permission_enums` entry that resolves to a class not
     * implementing the contract is rejected.
     *
     * @return void
     */
    public function testPermissionEnumWrongContractIsRejected(): void
    {
        /** @var \Illuminate\Contracts\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class);
        $config->set('authorization.permission_enums', [stdClass::class]);

        $this->expectException(InvalidAuthorizationConfigException::class);

        ConfigValidator::validate((array) $config->get('authorization'), $this->app);
    }

    /**
     * A null `principal_resolver` is rejected — the package ships
     * a safe default that consumers can fall back to explicitly.
     *
     * @return void
     */
    public function testNullPrincipalResolverIsRejected(): void
    {
        /** @var \Illuminate\Contracts\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class);
        $config->set('authorization.principal_resolver', null);

        try {
            ConfigValidator::validate((array) $config->get('authorization'), $this->app);
            self::fail('Expected InvalidAuthorizationConfigException was not thrown.');
        } catch (InvalidAuthorizationConfigException $exception) {
            self::assertSame('authorization.principal_resolver', $exception->getConfigKey());
            self::assertStringContainsString('NullPrincipalResolver', $exception->getReason());
        }
    }

    /**
     * A `principal_resolver` value that does not implement the
     * contract is rejected.
     *
     * @return void
     */
    public function testPrincipalResolverWrongContractIsRejected(): void
    {
        /** @var \Illuminate\Contracts\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class);
        $config->set('authorization.principal_resolver', stdClass::class);

        $this->expectException(InvalidAuthorizationConfigException::class);

        ConfigValidator::validate((array) $config->get('authorization'), $this->app);
    }

    /**
     * The shipped `NullPrincipalResolver` passes.
     *
     * @return void
     */
    public function testShippedPrincipalResolverPasses(): void
    {
        /** @var \Illuminate\Contracts\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class);
        $config->set('authorization.principal_resolver', NullPrincipalResolver::class);

        ConfigValidator::validate((array) $config->get('authorization'), $this->app);

        self::assertTrue(true);
    }

    /**
     * A non-null `policy_store` that does not implement the
     * contract is rejected.
     *
     * @return void
     */
    public function testPolicyStoreWrongContractIsRejected(): void
    {
        /** @var \Illuminate\Contracts\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class);
        $config->set('authorization.policy_store', stdClass::class);

        $this->expectException(InvalidAuthorizationConfigException::class);

        ConfigValidator::validate((array) $config->get('authorization'), $this->app);
    }

    /**
     * An unknown `cache.store` name is rejected with a helpful
     * message identifying the missing store.
     *
     * @return void
     */
    public function testUnknownCacheStoreIsRejected(): void
    {
        /** @var \Illuminate\Contracts\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class);
        $config->set('authorization.cache.store', 'does-not-exist');

        try {
            ConfigValidator::validate((array) $config->get('authorization'), $this->app);
            self::fail('Expected InvalidAuthorizationConfigException was not thrown.');
        } catch (InvalidAuthorizationConfigException $exception) {
            self::assertSame('authorization.cache.store', $exception->getConfigKey());
            self::assertStringContainsString('does-not-exist', $exception->getReason());
        }
    }

    /**
     * A configured cache store (`array` is always available in
     * Testbench) passes validation.
     *
     * @return void
     */
    public function testKnownCacheStorePasses(): void
    {
        /** @var \Illuminate\Contracts\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class);
        $config->set('authorization.cache.store', 'array');

        ConfigValidator::validate((array) $config->get('authorization'), $this->app);

        self::assertTrue(true);
    }

    /**
     * Non-string `permission_enums` entries are caught before any
     * class lookup runs.
     *
     * @dataProvider malformedPermissionEnumEntries
     *
     * @param  mixed  $entry
     * @return void
     */
    #[DataProvider('malformedPermissionEnumEntries')]
    public function testMalformedPermissionEnumEntryIsRejected(mixed $entry): void
    {
        /** @var \Illuminate\Contracts\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class);
        $config->set('authorization.permission_enums', [$entry]);

        $this->expectException(InvalidAuthorizationConfigException::class);

        ConfigValidator::validate((array) $config->get('authorization'), $this->app);
    }

    /**
     * Non-string / non-empty samples for the data provider.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function malformedPermissionEnumEntries(): iterable
    {
        yield 'empty-string' => [''];
        yield 'integer'      => [42];
        yield 'array'        => [[]];
        yield 'null'         => [null];
    }
}
