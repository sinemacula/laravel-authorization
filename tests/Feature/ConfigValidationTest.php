<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Config\ConfigValidator;
use SineMacula\Laravel\Authorization\Enums\GateConflictMode;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;
use SineMacula\Laravel\Authorization\Registrars\BladeDirectiveRegistrar;
use SineMacula\Laravel\Authorization\Registrars\EventListenerRegistrar;
use SineMacula\Laravel\Authorization\Registrars\GateRegistrar;
use SineMacula\Laravel\Authorization\Resolvers\NullPrincipalResolver;
use Tests\Feature\Stubs\Enums\PermissionEnum;
use Tests\TestCase;

/**
 * Feature coverage for the boot-time config validator.
 *
 * Every supported key gets a rejection case (type mismatch, missing class,
 * wrong contract, unknown cache store) and a happy-path case so the defaults
 * keep passing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 * @SuppressWarnings("php:S1448")
 * @SuppressWarnings("php:S4144")
 */
#[CoversClass(ConfigValidator::class)]
#[CoversClass(InvalidAuthorizationConfigException::class)]
#[CoversClass(AuthorizationServiceProvider::class)]
#[CoversClass(GateRegistrar::class)]
#[CoversClass(BladeDirectiveRegistrar::class)]
#[CoversClass(EventListenerRegistrar::class)]
final class ConfigValidationTest extends TestCase
{
    /**
     * The shipped defaults pass validation end-to-end — booting the provider
     * with the merged config must not throw.
     *
     * @return void
     */
    public function testDefaultConfigPassesValidation(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject

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
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.permission_enums', [PermissionEnum::class]);

        ConfigValidator::validate((array) $config->get('authorization'), $this->app);

        self::assertTrue(true);
    }

    /**
     * `gate.on_conflict` outside the three sentinels is rejected with a pointer
     * to the offending key.
     *
     * @return void
     */
    public function testInvalidGateOnConflictIsRejected(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.gate.on_conflict', 'explode');

        try {
            ConfigValidator::validate((array) $config->get('authorization'), $this->app);
            self::fail('Expected InvalidAuthorizationConfigException was not thrown.');
        } catch (InvalidAuthorizationConfigException $exception) {
            self::assertSame('authorization.gate.on_conflict', $exception->getConfigKey());
            self::assertStringContainsString('\'explode\'', $exception->getReason());
        }
    }

    /**
     * A `permission_enums` entry that does not resolve to a class is rejected
     * with a concrete error.
     *
     * @return void
     */
    public function testPermissionEnumMissingClassIsRejected(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.permission_enums', ['App\Does\Not\Exist']);

        try {
            ConfigValidator::validate((array) $config->get('authorization'), $this->app);
            self::fail('Expected InvalidAuthorizationConfigException was not thrown.');
        } catch (InvalidAuthorizationConfigException $exception) {
            self::assertSame('authorization.permission_enums.0', $exception->getConfigKey());
            self::assertStringContainsString('does not exist', $exception->getReason());
        }
    }

    /**
     * A `permission_enums` entry that resolves to a class not implementing the
     * contract is rejected.
     *
     * @return void
     */
    public function testPermissionEnumWrongContractIsRejected(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.permission_enums', [\stdClass::class]);

        $this->expectException(InvalidAuthorizationConfigException::class);

        ConfigValidator::validate((array) $config->get('authorization'), $this->app);
    }

    /**
     * A null `principal_resolver` is rejected — the package ships a safe
     * default that consumers can fall back to explicitly.
     *
     * @return void
     */
    public function testNullPrincipalResolverIsRejected(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
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
     * A `principal_resolver` value that does not implement the contract is
     * rejected.
     *
     * @return void
     */
    public function testPrincipalResolverWrongContractIsRejected(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.principal_resolver', \stdClass::class);

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
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.principal_resolver', NullPrincipalResolver::class);

        ConfigValidator::validate((array) $config->get('authorization'), $this->app);

        self::assertTrue(true);
    }

    /**
     * A non-null `policy_store` that does not implement the contract is
     * rejected.
     *
     * @return void
     */
    public function testPolicyStoreWrongContractIsRejected(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.policy_store', \stdClass::class);

        $this->expectException(InvalidAuthorizationConfigException::class);

        ConfigValidator::validate((array) $config->get('authorization'), $this->app);
    }

    /**
     * An unknown `cache.store` name is rejected with a helpful message
     * identifying the missing store.
     *
     * @return void
     */
    public function testUnknownCacheStoreIsRejected(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
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
     * A configured cache store (`array` is always available in Testbench)
     * passes validation.
     *
     * @return void
     */
    public function testKnownCacheStorePasses(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.cache.store', 'array');

        ConfigValidator::validate((array) $config->get('authorization'), $this->app);

        self::assertTrue(true);
    }

    /**
     * Non-string / non-empty samples for the data provider.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function malformedPermissionEnumEntries(): iterable
    {
        yield 'empty-string' => [''];
        yield 'integer' => [42];
        yield 'array' => [[]];
        yield 'null' => [null];
    }

    /**
     * Non-string `permission_enums` entries are caught before any class lookup
     * runs.
     *
     * @param  mixed  $entry
     * @return void
     */
    #[DataProvider('malformedPermissionEnumEntries')]
    public function testMalformedPermissionEnumEntryIsRejected(mixed $entry): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.permission_enums', [$entry]);

        $this->expectException(InvalidAuthorizationConfigException::class);

        ConfigValidator::validate((array) $config->get('authorization'), $this->app);
    }

    /**
     * Passing an already-coerced `GateConflictMode` value skips the string path
     * and passes validation.
     *
     * @return void
     */
    public function testGateOnConflictAcceptsEnumInstance(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.gate.on_conflict', GateConflictMode::THROW);

        ConfigValidator::validate((array) $config->get('authorization'), $this->app);

        self::assertTrue(true);
    }

    /**
     * The validator lists every enum-backed sentinel in its rejection message —
     * the operator gets the accepted set verbatim without having to find the
     * enum source.
     *
     * @return void
     */
    public function testGateOnConflictRejectionListsEveryEnumSentinel(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.gate.on_conflict', 'Log');

        try {
            ConfigValidator::validate((array) $config->get('authorization'), $this->app);
            self::fail('Expected InvalidAuthorizationConfigException was not thrown.');
        } catch (InvalidAuthorizationConfigException $exception) {
            $reason = $exception->getReason();

            self::assertStringContainsString('\'log\'', $reason);
            self::assertStringContainsString('\'throw\'', $reason);
            self::assertStringContainsString('\'overwrite\'', $reason);
            self::assertStringContainsString('\'Log\' (string)', $reason);
        }
    }

    // ------------------------------------------------------------------
    // Mutation-kill: exception message shapes (Concat / ConcatOperandRemoval)
    // ------------------------------------------------------------------

    /**
     * `permission_enums` wrong-contract rejection message includes both the
     * class name and the contract name. Kills Concat and ConcatOperandRemoval
     * mutants on line 81.
     *
     * @return void
     */
    public function testPermissionEnumWrongContractMessageShape(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.permission_enums', [\stdClass::class]);

        try {
            ConfigValidator::validate((array) $config->get('authorization'), $this->app);
            self::fail('Expected InvalidAuthorizationConfigException was not thrown.');
        } catch (InvalidAuthorizationConfigException $exception) {
            $reason = $exception->getReason();
            self::assertStringContainsString(\stdClass::class, $reason);
            self::assertStringContainsString('does not implement', $reason);
            self::assertStringContainsString('PermissionEnum', $reason);
        }
    }

    /**
     * `permission_providers` wrong-contract rejection message includes both the
     * class name and the contract name. Kills Concat and ConcatOperandRemoval
     * mutants on line 111.
     *
     * @return void
     */
    public function testPermissionProviderWrongContractMessageShape(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.permission_providers', [\stdClass::class]);

        try {
            ConfigValidator::validate((array) $config->get('authorization'), $this->app);
            self::fail('Expected InvalidAuthorizationConfigException was not thrown.');
        } catch (InvalidAuthorizationConfigException $exception) {
            $reason = $exception->getReason();
            self::assertStringContainsString(\stdClass::class, $reason);
            self::assertStringContainsString('does not implement', $reason);
            self::assertStringContainsString('PermissionProvider', $reason);
        }
    }

    /**
     * `gate.on_conflict` rejection message includes the value description and
     * the accepted sentinel list. Kills Concat and ConcatOperandRemoval mutants
     * on line 139.
     *
     * @return void
     */
    public function testGateOnConflictRejectionMessageShape(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.gate.on_conflict', 42);

        try {
            ConfigValidator::validate((array) $config->get('authorization'), $this->app);
            self::fail('Expected InvalidAuthorizationConfigException was not thrown.');
        } catch (InvalidAuthorizationConfigException $exception) {
            $reason = $exception->getReason();
            // Must contain "expected one of [...]"
            self::assertStringContainsString('expected one of', $reason);
            // Must contain the offending value description
            self::assertStringContainsString('42', $reason);
            self::assertStringContainsString('int', $reason);
            // Must contain at least one sentinel
            self::assertStringContainsString('\'log\'', $reason);
        }
    }

    /**
     * `principal_resolver` rejection message when passed a non-string. Kills
     * Concat and ConcatOperandRemoval on line 157 (via assertImplementsContract
     * at line 262).
     *
     * @return void
     */
    public function testPrincipalResolverNonStringMessageShape(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.principal_resolver', 42);

        try {
            ConfigValidator::validate((array) $config->get('authorization'), $this->app);
            self::fail('Expected InvalidAuthorizationConfigException was not thrown.');
        } catch (InvalidAuthorizationConfigException $exception) {
            $reason = $exception->getReason();
            self::assertStringContainsString('expected a class-string', $reason);
            self::assertStringContainsString('42', $reason);
            self::assertStringContainsString('int', $reason);
        }
    }

    /**
     * `assertImplementsContract` with a missing class. Kills Concat mutants on
     * line 244 (via the "does not exist" branch).
     *
     * @return void
     */
    public function testAssertImplementsContractMissingClassMessageShape(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.principal_resolver', 'App\Does\Not\Exist');

        try {
            ConfigValidator::validate((array) $config->get('authorization'), $this->app);
            self::fail('Expected InvalidAuthorizationConfigException was not thrown.');
        } catch (InvalidAuthorizationConfigException $exception) {
            $reason = $exception->getReason();
            self::assertStringContainsString('App\Does\Not\Exist', $reason);
            self::assertStringContainsString('does not exist', $reason);
        }
    }

    /**
     * `assertImplementsContract` with a class that doesn't implement the
     * contract. Kills Concat mutants on line 262 (the "does not implement"
     * branch) and the LogicalAnd on line 269.
     *
     * @return void
     */
    public function testAssertImplementsContractWrongContractMessageShape(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.principal_resolver', \stdClass::class);

        try {
            ConfigValidator::validate((array) $config->get('authorization'), $this->app);
            self::fail('Expected InvalidAuthorizationConfigException was not thrown.');
        } catch (InvalidAuthorizationConfigException $exception) {
            $reason = $exception->getReason();
            self::assertStringContainsString(\stdClass::class, $reason);
            self::assertStringContainsString('does not implement', $reason);
            self::assertStringContainsString('PrincipalResolver', $reason);
        }
    }

    /**
     * `cache.store` non-string rejection message shape. Kills Concat and
     * ConcatOperandRemoval on line 234 (via describe()).
     *
     * @return void
     */
    public function testCacheStoreNonStringMessageShape(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.cache.store', 42);

        try {
            ConfigValidator::validate((array) $config->get('authorization'), $this->app);
            self::fail('Expected InvalidAuthorizationConfigException was not thrown.');
        } catch (InvalidAuthorizationConfigException $exception) {
            $reason = $exception->getReason();
            self::assertStringContainsString('expected a cache-store name string', $reason);
            self::assertStringContainsString('42', $reason);
            self::assertStringContainsString('int', $reason);
        }
    }

    /**
     * `cache.store` empty string is rejected like non-string.
     *
     * @return void
     */
    public function testCacheStoreEmptyStringIsRejected(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.cache.store', '');

        $this->expectException(InvalidAuthorizationConfigException::class);

        ConfigValidator::validate((array) $config->get('authorization'), $this->app);
    }

    /**
     * Throw_ removal on line 266: if the assertImplementsContract throw is
     * removed, no exception occurs for a wrong-contract class. This test proves
     * the throw is essential.
     *
     * @return void
     */
    public function testAssertImplementsContractThrowIsEssential(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.policy_store', \stdClass::class);

        $this->expectException(InvalidAuthorizationConfigException::class);

        ConfigValidator::validate((array) $config->get('authorization'), $this->app);
    }

    /**
     * `permission_providers` non-array is rejected with a type description.
     * Kills Concat mutants on the permission_providers non-array branch.
     *
     * @return void
     */
    public function testPermissionProvidersNonArrayRejectionMessageShape(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.permission_providers', 'not-an-array');

        try {
            ConfigValidator::validate((array) $config->get('authorization'), $this->app);
            self::fail('Expected InvalidAuthorizationConfigException was not thrown.');
        } catch (InvalidAuthorizationConfigException $exception) {
            $reason = $exception->getReason();
            self::assertStringContainsString('expected an array', $reason);
            self::assertStringContainsString('string', $reason);
        }
    }

    /**
     * `permission_enums` non-array is rejected with a type description.
     *
     * @return void
     */
    public function testPermissionEnumsNonArrayRejectionMessageShape(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.permission_enums', 'not-an-array');

        try {
            ConfigValidator::validate((array) $config->get('authorization'), $this->app);
            self::fail('Expected InvalidAuthorizationConfigException was not thrown.');
        } catch (InvalidAuthorizationConfigException $exception) {
            $reason = $exception->getReason();
            self::assertStringContainsString('expected an array', $reason);
            self::assertStringContainsString('string', $reason);
        }
    }

    /**
     * `permission_providers` entry that is a missing class. Kills Concat
     * mutants on the "does not exist" branch for providers.
     *
     * @return void
     */
    public function testPermissionProviderMissingClassMessageShape(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.permission_providers', ['App\Missing\Provider']);

        try {
            ConfigValidator::validate((array) $config->get('authorization'), $this->app);
            self::fail('Expected InvalidAuthorizationConfigException was not thrown.');
        } catch (InvalidAuthorizationConfigException $exception) {
            $reason = $exception->getReason();
            self::assertStringContainsString('App\Missing\Provider', $reason);
            self::assertStringContainsString('does not exist', $reason);
        }
    }

    /**
     * `permission_providers` malformed entry (non-string / empty).
     *
     * @return void
     */
    public function testPermissionProviderMalformedEntryIsRejected(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.permission_providers', ['']);

        $this->expectException(InvalidAuthorizationConfigException::class);

        ConfigValidator::validate((array) $config->get('authorization'), $this->app);
    }

    /**
     * `tenant_resolver` with wrong contract is rejected. Kills the
     * assertImplementsContract path for tenant_resolver.
     *
     * @return void
     */
    public function testTenantResolverWrongContractIsRejected(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.tenant_resolver', \stdClass::class);

        try {
            ConfigValidator::validate((array) $config->get('authorization'), $this->app);
            self::fail('Expected InvalidAuthorizationConfigException was not thrown.');
        } catch (InvalidAuthorizationConfigException $exception) {
            $reason = $exception->getReason();
            self::assertStringContainsString(\stdClass::class, $reason);
            self::assertStringContainsString('does not implement', $reason);
            self::assertStringContainsString('TenantResolver', $reason);
        }
    }
}
