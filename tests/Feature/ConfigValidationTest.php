<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Config\ConfigValidator;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;
use SineMacula\Laravel\Authorization\Registrars\BladeDirectiveRegistrar;
use SineMacula\Laravel\Authorization\Registrars\GateRegistrar;
use SineMacula\Laravel\Authorization\Resolvers\AuthGuardSubjectResolver;
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
        $config = $this->container()->make(ConfigRepository::class);

        (new AuthorizationServiceProvider($this->container()))->boot();

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
        $config = $this->container()->make(ConfigRepository::class);
        $config->set('authorization.permission_enums', [PermissionEnum::class]);

        ConfigValidator::validate($this->authorizationConfig(), $this->container());

        self::assertTrue(true);
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
        $config = $this->container()->make(ConfigRepository::class);
        $config->set('authorization.permission_enums', ['App\Does\Not\Exist']);

        try {
            ConfigValidator::validate($this->authorizationConfig(), $this->container());
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
        $config = $this->container()->make(ConfigRepository::class);
        $config->set('authorization.permission_enums', [\stdClass::class]);

        $this->expectException(InvalidAuthorizationConfigException::class);

        ConfigValidator::validate($this->authorizationConfig(), $this->container());
    }

    /**
     * A null `subject_resolver` is rejected — the package ships a default that
     * consumers can fall back to explicitly.
     *
     * @return void
     */
    public function testNullSubjectResolverIsRejected(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->container()->make(ConfigRepository::class);
        $config->set('authorization.subject_resolver', null);

        try {
            ConfigValidator::validate($this->authorizationConfig(), $this->container());
            self::fail('Expected InvalidAuthorizationConfigException was not thrown.');
        } catch (InvalidAuthorizationConfigException $exception) {
            self::assertSame('authorization.subject_resolver', $exception->getConfigKey());
            self::assertStringContainsString('AuthGuardSubjectResolver', $exception->getReason());
        }
    }

    /**
     * A `subject_resolver` value that does not implement the contract is
     * rejected.
     *
     * @return void
     */
    public function testSubjectResolverWrongContractIsRejected(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->container()->make(ConfigRepository::class);
        $config->set('authorization.subject_resolver', \stdClass::class);

        $this->expectException(InvalidAuthorizationConfigException::class);

        ConfigValidator::validate($this->authorizationConfig(), $this->container());
    }

    /**
     * The shipped `AuthGuardSubjectResolver` passes.
     *
     * @return void
     */
    public function testShippedSubjectResolverPasses(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->container()->make(ConfigRepository::class);
        $config->set('authorization.subject_resolver', AuthGuardSubjectResolver::class);

        ConfigValidator::validate($this->authorizationConfig(), $this->container());

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
        $config = $this->container()->make(ConfigRepository::class);
        $config->set('authorization.policy_store', \stdClass::class);

        $this->expectException(InvalidAuthorizationConfigException::class);

        ConfigValidator::validate($this->authorizationConfig(), $this->container());
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
        $config = $this->container()->make(ConfigRepository::class);
        $config->set('authorization.cache.store', 'does-not-exist');

        try {
            ConfigValidator::validate($this->authorizationConfig(), $this->container());
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
        $config = $this->container()->make(ConfigRepository::class);
        $config->set('authorization.cache.store', 'array');

        ConfigValidator::validate($this->authorizationConfig(), $this->container());

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
        $config = $this->container()->make(ConfigRepository::class);
        $config->set('authorization.permission_enums', [$entry]);

        $this->expectException(InvalidAuthorizationConfigException::class);

        ConfigValidator::validate($this->authorizationConfig(), $this->container());
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
        $config = $this->container()->make(ConfigRepository::class);
        $config->set('authorization.permission_enums', [\stdClass::class]);

        try {
            ConfigValidator::validate($this->authorizationConfig(), $this->container());
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
        $config = $this->container()->make(ConfigRepository::class);
        $config->set('authorization.permission_providers', [\stdClass::class]);

        try {
            ConfigValidator::validate($this->authorizationConfig(), $this->container());
            self::fail('Expected InvalidAuthorizationConfigException was not thrown.');
        } catch (InvalidAuthorizationConfigException $exception) {
            $reason = $exception->getReason();
            self::assertStringContainsString(\stdClass::class, $reason);
            self::assertStringContainsString('does not implement', $reason);
            self::assertStringContainsString('PermissionProvider', $reason);
        }
    }

    /**
     * `subject_resolver` rejection message when passed a non-string names the
     * type it was given.
     *
     * @return void
     */
    public function testSubjectResolverNonStringMessageShape(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->container()->make(ConfigRepository::class);
        $config->set('authorization.subject_resolver', 42);

        try {
            ConfigValidator::validate($this->authorizationConfig(), $this->container());
            self::fail('Expected InvalidAuthorizationConfigException was not thrown.');
        } catch (InvalidAuthorizationConfigException $exception) {
            $reason = $exception->getReason();
            self::assertSame('authorization.subject_resolver', $exception->getConfigKey());
            self::assertSame('expected a class-string, got int.', $reason);
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
        $config = $this->container()->make(ConfigRepository::class);
        $config->set('authorization.subject_resolver', 'App\Does\Not\Exist');

        try {
            ConfigValidator::validate($this->authorizationConfig(), $this->container());
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
        $config = $this->container()->make(ConfigRepository::class);
        $config->set('authorization.subject_resolver', \stdClass::class);

        try {
            ConfigValidator::validate($this->authorizationConfig(), $this->container());
            self::fail('Expected InvalidAuthorizationConfigException was not thrown.');
        } catch (InvalidAuthorizationConfigException $exception) {
            $reason = $exception->getReason();
            self::assertStringContainsString(\stdClass::class, $reason);
            self::assertStringContainsString('does not implement', $reason);
            self::assertStringContainsString('SubjectResolver', $reason);
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
        $config = $this->container()->make(ConfigRepository::class);
        $config->set('authorization.cache.store', 42);

        try {
            ConfigValidator::validate($this->authorizationConfig(), $this->container());
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
        $config = $this->container()->make(ConfigRepository::class);
        $config->set('authorization.cache.store', '');

        $this->expectException(InvalidAuthorizationConfigException::class);

        ConfigValidator::validate($this->authorizationConfig(), $this->container());
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
        $config = $this->container()->make(ConfigRepository::class);
        $config->set('authorization.policy_store', \stdClass::class);

        $this->expectException(InvalidAuthorizationConfigException::class);

        ConfigValidator::validate($this->authorizationConfig(), $this->container());
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
        $config = $this->container()->make(ConfigRepository::class);
        $config->set('authorization.permission_providers', 'not-an-array');

        try {
            ConfigValidator::validate($this->authorizationConfig(), $this->container());
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
        $config = $this->container()->make(ConfigRepository::class);
        $config->set('authorization.permission_enums', 'not-an-array');

        try {
            ConfigValidator::validate($this->authorizationConfig(), $this->container());
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
        $config = $this->container()->make(ConfigRepository::class);
        $config->set('authorization.permission_providers', ['App\Missing\Provider']);

        try {
            ConfigValidator::validate($this->authorizationConfig(), $this->container());
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
        $config = $this->container()->make(ConfigRepository::class);
        $config->set('authorization.permission_providers', ['']);

        $this->expectException(InvalidAuthorizationConfigException::class);

        ConfigValidator::validate($this->authorizationConfig(), $this->container());
    }
}
