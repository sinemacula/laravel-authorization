<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Config\ConfigValidator;
use SineMacula\Laravel\Authorization\Contracts\ResourceTenantResolver;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Resolvers\AuthGuardSubjectResolver;
use SineMacula\Laravel\Authorization\Resolvers\FlatTenantTree;
use SineMacula\Laravel\Authorization\Resolvers\NoResourceTenant;
use Tests\Feature\Stubs\Contracts\PermissionEnumInterface;
use Tests\Feature\Stubs\CustomPermission;
use Tests\Feature\Stubs\CustomPolicy;
use Tests\Feature\Stubs\CustomRole;
use Tests\Feature\Stubs\Enums\IntBackedPermissionEnum;
use Tests\Feature\Stubs\Enums\PermissionEnum;
use Tests\Feature\Stubs\FixedResourceTenantResolver;
use Tests\Feature\Stubs\StubSubjectResolver;
use Tests\Feature\Stubs\StubTenantTree;
use Tests\TestCase;

/**
 * Feature tests for the boot-time validation of `authorization.models.*`, the
 * connection, the backing of `authorization.permission_enums`, the subject
 * resolver, the tenant tree, the resource tenant resolver and the policy
 * limits.
 *
 * Each model entry must name an existing class that is the shipped model or a
 * subclass of it, and each permission enum must be backed by strings; anything
 * else is refused with the offending key.
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
final class ConfigValidatorTest extends TestCase
{
    /** @var string The reason a missing resource tenant resolver is refused for. */
    private const string RESOURCE_TENANT_RESOLVER_REQUIRED = 'a resource tenant resolver class is required; set it to \\'
        . NoResourceTenant::class
        . ' to read no resource\'s tenant.';

    /**
     * The shipped models pass validation.
     *
     * @return void
     */
    public function testShippedModelsPass(): void
    {
        $this->validateWithModels([
            'role'       => Role::class,
            'permission' => Permission::class,
            'policy'     => Policy::class,
        ]);

        $this->expectNotToPerformAssertions();
    }

    /**
     * Subclasses of the shipped models pass validation.
     *
     * @return void
     */
    public function testSubclassesOfShippedModelsPass(): void
    {
        $this->validateWithModels([
            'role'       => CustomRole::class,
            'permission' => CustomPermission::class,
            'policy'     => CustomPolicy::class,
        ]);

        $this->expectNotToPerformAssertions();
    }

    /**
     * A `models` block with keys left out passes: each missing key falls back
     * to the shipped model.
     *
     * @return void
     */
    public function testMissingModelKeysPass(): void
    {
        $this->validateWithModels([]);

        $this->expectNotToPerformAssertions();
    }

    /**
     * A config with no `models` block at all passes.
     *
     * @return void
     */
    public function testAbsentModelsBlockPasses(): void
    {
        $config = $this->authorizationConfig();

        unset($config['models']);

        ConfigValidator::validate($config, $this->app);

        $this->expectNotToPerformAssertions();
    }

    /**
     * The longest an entry lives may be any whole number of seconds from 1, and
     * defaults when it is not set.
     *
     * @return void
     */
    public function testCacheLifetimesFromOneSecondPass(): void
    {
        foreach ([1, 300] as $ttl) {
            $config                 = $this->authorizationConfig();
            $config['cache']['ttl'] = $ttl;

            ConfigValidator::validate($config, $this->app);
        }

        $config = $this->authorizationConfig();
        unset($config['cache']['ttl']);

        ConfigValidator::validate($config, $this->app);

        $this->expectNotToPerformAssertions();
    }

    /**
     * A cache lifetime below a second, or that is not a whole number, is
     * refused: there is no "forever".
     *
     * @return void
     */
    public function testCacheLifetimesBelowASecondAreRejected(): void
    {
        foreach ([0 => '0 (int)', -5 => '-5 (int)'] as $ttl => $described) {
            $config                 = $this->authorizationConfig();
            $config['cache']['ttl'] = $ttl;

            $this->assertRejected(
                fn () => ConfigValidator::validate($config, $this->app),
                'authorization.cache.ttl',
                "expected a whole number of seconds of at least 1, got {$described}.",
            );
        }

        $config                 = $this->authorizationConfig();
        $config['cache']['ttl'] = '300';

        $this->assertRejected(
            fn () => ConfigValidator::validate($config, $this->app),
            'authorization.cache.ttl',
            'expected a whole number of seconds of at least 1, got \'300\' (string).',
        );
    }

    /**
     * The policy limits pass from 1, and each limit, or all of them, may be
     * left unset or null.
     *
     * @return void
     */
    public function testPolicyLimitsFromOnePass(): void
    {
        $config                       = $this->authorizationConfig();
        $config['policies']['limits'] = ['document_bytes' => 1, 'statements' => 1, 'conditions' => 1, 'pattern_length' => 1];

        ConfigValidator::validate($config, $this->app);

        unset($config['policies']['limits']['statements']);
        $config['policies']['limits']['conditions'] = null;

        ConfigValidator::validate($config, $this->app);

        unset($config['policies']);

        ConfigValidator::validate($config, $this->app);

        $this->expectNotToPerformAssertions();
    }

    /**
     * Return each policy limit set below 1 or to something that is not a whole
     * number, with how it is described.
     *
     * @return iterable<string, array{string, mixed, string}>
     */
    public static function invalidPolicyLimits(): iterable
    {
        foreach (['document_bytes', 'statements', 'conditions', 'pattern_length'] as $key) {
            yield "{$key} of 0" => [$key, 0, '0 (int)'];
            yield "{$key} below 0" => [$key, -1, '-1 (int)'];
            yield "{$key} as a string" => [$key, '10', '\'10\' (string)'];
            yield "{$key} as a float" => [$key, 10.5, '10.5 (float)'];
        }
    }

    /**
     * A policy limit below 1, or that is not a whole number, is refused with
     * its key.
     *
     * @param  string  $key
     * @param  mixed  $limit
     * @param  string  $described
     * @return void
     */
    #[DataProvider('invalidPolicyLimits')]
    public function testInvalidPolicyLimitIsRejected(string $key, mixed $limit, string $described): void
    {
        $config                             = $this->authorizationConfig();
        $config['policies']['limits'][$key] = $limit;

        $this->assertRejected(
            fn () => ConfigValidator::validate($config, $this->app),
            "authorization.policies.limits.{$key}",
            "expected a whole number of at least 1, got {$described}.",
        );
    }

    /**
     * Policy limits that are not an array are refused.
     *
     * @return void
     */
    public function testNonArrayPolicyLimitsAreRejected(): void
    {
        $config                       = $this->authorizationConfig();
        $config['policies']['limits'] = 100;

        $this->assertRejected(
            fn () => ConfigValidator::validate($config, $this->app),
            'authorization.policies.limits',
            'expected an array of limits, got 100 (int).',
        );
    }

    /**
     * A `models` block that is not an array is refused.
     *
     * @return void
     */
    public function testNonArrayModelsBlockIsRejected(): void
    {
        $config           = $this->authorizationConfig();
        $config['models'] = 'role';

        $this->assertRejected(
            fn () => ConfigValidator::validate($config, $this->app),
            'authorization.models',
            'expected an array of model class names, got \'role\' (string).',
        );
    }

    /**
     * Invalid `models.*` entries with the reason each is refused for.
     *
     * @return iterable<string, array{string, mixed, string}>
     */
    public static function invalidModelProvider(): iterable
    {
        yield 'null role' => ['role', null, 'expected a class-string, got \'null\' (null).'];
        yield 'integer role' => ['role', 42, 'expected a class-string, got 42 (int).'];
        yield 'empty role' => ['role', '', 'expected a class-string, got \'\' (string).'];
        yield 'missing role class' => ['role', 'App\Models\Missing', 'class \'App\Models\Missing\' does not exist.'];
        yield 'unrelated role class' => ['role', \stdClass::class, 'class \'stdClass\' is neither ' . Role::class . ' nor a subclass of it.'];
        yield 'permission as role' => ['role', Permission::class, 'class \'' . Permission::class . '\' is neither ' . Role::class . ' nor a subclass of it.'];
        yield 'role as permission' => ['permission', Role::class, 'class \'' . Role::class . '\' is neither ' . Permission::class . ' nor a subclass of it.'];
        yield 'role subclass as policy' => ['policy', CustomRole::class, 'class \'' . CustomRole::class . '\' is neither ' . Policy::class . ' nor a subclass of it.'];
    }

    /**
     * Every invalid `models.*` entry is refused with its own key and reason.
     *
     * @param  string  $key
     * @param  mixed  $class
     * @param  string  $reason
     * @return void
     */
    #[DataProvider('invalidModelProvider')]
    public function testInvalidModelEntryIsRejected(string $key, mixed $class, string $reason): void
    {
        $this->assertRejected(
            fn () => $this->validateWithModels([$key => $class]),
            "authorization.models.{$key}",
            $reason,
        );
    }

    /**
     * A bad `models.*` entry fails the provider's boot.
     *
     * @return void
     */
    public function testInvalidModelEntryFailsBoot(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.models.role', \stdClass::class);

        $this->assertRejected(
            fn () => (new AuthorizationServiceProvider($this->app))->boot(),
            'authorization.models.role',
            'class \'stdClass\' is neither ' . Role::class . ' nor a subclass of it.',
        );
    }

    /**
     * An unset or empty connection, and a configured connection's name, pass
     * validation.
     *
     * @return void
     */
    public function testUnsetEmptyAndConfiguredConnectionsPass(): void
    {
        foreach ([null, '', 'testing'] as $connection) {
            $this->validateWithConnection($connection);
        }

        $this->expectNotToPerformAssertions();
    }

    /**
     * A connection setting that is not a string is refused.
     *
     * @return void
     */
    public function testNonStringConnectionIsRejected(): void
    {
        $this->assertRejected(
            fn () => $this->validateWithConnection(5),
            'authorization.connection',
            'expected a database connection name, got 5 (int).',
        );
    }

    /**
     * A connection the application does not configure is refused at boot,
     * rather than on the first query.
     *
     * @return void
     */
    public function testUnknownConnectionIsRejected(): void
    {
        $this->assertRejected(
            fn () => $this->validateWithConnection('missing'),
            'authorization.connection',
            'database connection \'missing\' is not configured.',
        );
    }

    /**
     * A string-backed permission enum passes validation.
     *
     * @return void
     */
    public function testStringBackedPermissionEnumPasses(): void
    {
        $this->validateWithPermissionEnums([PermissionEnum::class]);

        $this->expectNotToPerformAssertions();
    }

    /**
     * A permission enum backed by integers is refused, since a case's value is
     * the permission name.
     *
     * @return void
     */
    public function testIntBackedPermissionEnumIsRejected(): void
    {
        $this->assertRejected(
            fn () => $this->validateWithPermissionEnums([PermissionEnum::class, IntBackedPermissionEnum::class]),
            'authorization.permission_enums.1',
            'enum \'' . IntBackedPermissionEnum::class . '\' must be backed by strings, since each case\'s value is a permission name.',
        );
    }

    /**
     * An interface extending the contract is refused, since it is not an enum.
     *
     * @return void
     */
    public function testPermissionEnumInterfaceIsRejected(): void
    {
        $this->assertRejected(
            fn () => $this->validateWithPermissionEnums([PermissionEnumInterface::class]),
            'authorization.permission_enums.0',
            'enum \'' . PermissionEnumInterface::class . '\' must be backed by strings, since each case\'s value is a permission name.',
        );
    }

    /**
     * A permission enum backed by integers fails the provider's boot.
     *
     * @return void
     */
    public function testIntBackedPermissionEnumFailsBoot(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.permission_enums', [IntBackedPermissionEnum::class]);

        $this->assertRejected(
            fn () => (new AuthorizationServiceProvider($this->app))->boot(),
            'authorization.permission_enums.0',
            'enum \'' . IntBackedPermissionEnum::class . '\' must be backed by strings, since each case\'s value is a permission name.',
        );
    }

    /**
     * Provide `permission_enums` entries with whether each is a string-backed
     * permission enum.
     *
     * @return iterable<string, array{mixed, bool}>
     */
    public static function permissionEnumEntryProvider(): iterable
    {
        yield 'string-backed enum' => [PermissionEnum::class, true];

        yield 'integer-backed enum' => [IntBackedPermissionEnum::class, false];

        yield 'contract interface' => [PermissionEnumInterface::class, false];

        yield 'class not implementing the contract' => [\stdClass::class, false];

        yield 'non-string entry' => [123, false];
    }

    /**
     * Only a string-backed enum implementing the contract is a usable
     * `permission_enums` entry for the code that reads the list at run time.
     *
     * @param  mixed  $class
     * @param  bool  $expected
     * @return void
     */
    #[DataProvider('permissionEnumEntryProvider')]
    public function testIdentifiesAStringBackedPermissionEnum(mixed $class, bool $expected): void
    {
        self::assertSame($expected, ConfigValidator::isStringBackedPermissionEnum($class));
    }

    /**
     * The shipped subject resolver, and any class implementing the contract,
     * pass validation.
     *
     * @return void
     */
    public function testSubjectResolverImplementingTheContractPasses(): void
    {
        $this->validateWithSubjectResolver(AuthGuardSubjectResolver::class);
        $this->validateWithSubjectResolver(StubSubjectResolver::class);

        $this->expectNotToPerformAssertions();
    }

    /**
     * Application access maps application names to permission names; an empty
     * map, the default, passes.
     *
     * @return void
     */
    public function testApplicationAccessMapsApplicationsToPermissions(): void
    {
        $config = $this->authorizationConfig();

        foreach ([[], ['admin' => 'admin:access', 'mobile' => 'mobile:access']] as $access) {
            $config['application_access'] = $access;

            ConfigValidator::validate($config, $this->app);
        }

        unset($config['application_access']);

        ConfigValidator::validate($config, $this->app);

        $this->expectNotToPerformAssertions();
    }

    /**
     * Invalid `application_access` values with the reason each is refused for.
     *
     * @return iterable<string, array{mixed, string}>
     */
    public static function invalidApplicationAccessProvider(): iterable
    {
        $entry = 'each application name must map to a permission name, both non-empty strings.';

        yield 'not an array' => ['admin:access', 'expected an array of application names to permission names.'];
        yield 'a list' => [['admin:access'], $entry];
        yield 'an empty application' => [['' => 'admin:access'], $entry];
        yield 'a permission that is not a string' => [['admin' => 1], $entry];
        yield 'an empty permission' => [['admin' => ''], $entry];
    }

    /**
     * Every invalid `application_access` value is refused with its reason.
     *
     * @param  mixed  $access
     * @param  string  $reason
     * @return void
     */
    #[DataProvider('invalidApplicationAccessProvider')]
    public function testInvalidApplicationAccessIsRejected(mixed $access, string $reason): void
    {
        $config                       = $this->authorizationConfig();
        $config['application_access'] = $access;

        $this->assertRejected(fn () => ConfigValidator::validate($config, $this->app), 'authorization.application_access', $reason);
    }

    /**
     * The shipped flat tenant tree, and any class implementing the contract,
     * pass validation.
     *
     * @return void
     */
    public function testTenantTreeImplementingTheContractPasses(): void
    {
        $this->validateWithTenantTree(FlatTenantTree::class);
        $this->validateWithTenantTree(StubTenantTree::class);

        $this->expectNotToPerformAssertions();
    }

    /**
     * Invalid `tenant_tree` values with the reason each is refused for.
     *
     * @return iterable<string, array{mixed, string}>
     */
    public static function invalidTenantTreeProvider(): iterable
    {
        yield 'null' => [null, 'a tenant tree class is required; set it to \\' . FlatTenantTree::class . ' for a flat set of tenants.'];
        yield 'missing class' => ['App\Tenancy\Missing', 'class \'App\Tenancy\Missing\' does not exist.'];
        yield 'unrelated class' => [\stdClass::class, 'class \'stdClass\' does not implement ' . TenantTree::class . '.'];
    }

    /**
     * Every invalid `tenant_tree` value, null and a missing key included, is
     * refused with its reason: no tree never means a flat one by accident.
     *
     * @param  mixed  $tree
     * @param  string  $reason
     * @return void
     */
    #[DataProvider('invalidTenantTreeProvider')]
    public function testInvalidTenantTreeIsRejected(mixed $tree, string $reason): void
    {
        $this->assertRejected(fn () => $this->validateWithTenantTree($tree), 'authorization.tenant_tree', $reason);

        if ($tree !== null) {
            return;
        }

        $config = $this->authorizationConfig();
        unset($config['tenant_tree']);

        $this->assertRejected(fn () => ConfigValidator::validate($config, $this->app), 'authorization.tenant_tree', $reason);
    }

    /**
     * The shipped resource tenant resolver, and any class implementing the
     * contract, pass validation.
     *
     * @return void
     */
    public function testResourceTenantResolverImplementingTheContractPasses(): void
    {
        $this->validateWithResourceTenantResolver(NoResourceTenant::class);
        $this->validateWithResourceTenantResolver(FixedResourceTenantResolver::class);

        $this->expectNotToPerformAssertions();
    }

    /**
     * Invalid `resource_tenant_resolver` values with the reason each is refused
     * for.
     *
     * @return iterable<string, array{mixed, string}>
     */
    public static function invalidResourceTenantResolverProvider(): iterable
    {
        yield 'null' => [null, self::RESOURCE_TENANT_RESOLVER_REQUIRED];
        yield 'missing class' => ['App\Tenancy\Missing', 'class \'App\Tenancy\Missing\' does not exist.'];
        yield 'unrelated class' => [\stdClass::class, 'class \'stdClass\' does not implement ' . ResourceTenantResolver::class . '.'];
    }

    /**
     * Every invalid `resource_tenant_resolver` value, null included, is refused
     * with its reason: no resolver never means no resource's tenant by
     * accident.
     *
     * @param  mixed  $resolver
     * @param  string  $reason
     * @return void
     */
    #[DataProvider('invalidResourceTenantResolverProvider')]
    public function testInvalidResourceTenantResolverIsRejected(mixed $resolver, string $reason): void
    {
        $this->assertRejected(
            fn () => $this->validateWithResourceTenantResolver($resolver),
            'authorization.resource_tenant_resolver',
            $reason,
        );
    }

    /**
     * A config without a `resource_tenant_resolver` key is refused as null is.
     *
     * @return void
     */
    public function testMissingResourceTenantResolverIsRejected(): void
    {
        $config = $this->authorizationConfig();
        unset($config['resource_tenant_resolver']);

        $this->assertRejected(
            fn () => ConfigValidator::validate($config, $this->app),
            'authorization.resource_tenant_resolver',
            self::RESOURCE_TENANT_RESOLVER_REQUIRED,
        );
    }

    /**
     * A null `resource_tenant_resolver` fails the provider's boot.
     *
     * @return void
     */
    public function testNullResourceTenantResolverFailsBoot(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.resource_tenant_resolver', null);

        $this->assertRejected(
            fn () => (new AuthorizationServiceProvider($this->app))->boot(),
            'authorization.resource_tenant_resolver',
            self::RESOURCE_TENANT_RESOLVER_REQUIRED,
        );
    }

    /**
     * Invalid `subject_resolver` values with the reason each is refused for.
     *
     * @return iterable<string, array{mixed, string}>
     */
    public static function invalidSubjectResolverProvider(): iterable
    {
        yield 'null' => [null, 'a subject resolver class is required; set it to \\' . AuthGuardSubjectResolver::class . ' to decide about the user Laravel authenticated.'];
        yield 'integer' => [42, 'expected a class-string, got 42 (int).'];
        yield 'empty' => ['', 'expected a class-string, got \'\' (string).'];
        yield 'missing class' => ['App\Resolvers\Missing', 'class \'App\Resolvers\Missing\' does not exist.'];
        yield 'unrelated class' => [\stdClass::class, 'class \'stdClass\' does not implement ' . SubjectResolver::class . '.'];
    }

    /**
     * Every invalid `subject_resolver` value, null included, is refused with
     * its reason: no resolver never means no subject.
     *
     * @param  mixed  $resolver
     * @param  string  $reason
     * @return void
     */
    #[DataProvider('invalidSubjectResolverProvider')]
    public function testInvalidSubjectResolverIsRejected(mixed $resolver, string $reason): void
    {
        $this->assertRejected(
            fn () => $this->validateWithSubjectResolver($resolver),
            'authorization.subject_resolver',
            $reason,
        );
    }

    /**
     * A config without a `subject_resolver` key is refused as null is.
     *
     * @return void
     */
    public function testMissingSubjectResolverIsRejected(): void
    {
        $config = $this->authorizationConfig();
        unset($config['subject_resolver']);

        $this->assertRejected(
            fn () => ConfigValidator::validate($config, $this->app),
            'authorization.subject_resolver',
            'a subject resolver class is required; set it to \\' . AuthGuardSubjectResolver::class . ' to decide about the user Laravel authenticated.',
        );
    }

    /**
     * A null `subject_resolver` fails the provider's boot.
     *
     * @return void
     */
    public function testNullSubjectResolverFailsBoot(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.subject_resolver', null);

        $this->assertRejected(
            fn () => (new AuthorizationServiceProvider($this->app))->boot(),
            'authorization.subject_resolver',
            'a subject resolver class is required; set it to \\' . AuthGuardSubjectResolver::class . ' to decide about the user Laravel authenticated.',
        );
    }

    /**
     * Run the validator over the package config with the given
     * `subject_resolver`.
     *
     * @param  mixed  $resolver
     * @return void
     */
    private function validateWithSubjectResolver(mixed $resolver): void
    {
        $config                     = $this->authorizationConfig();
        $config['subject_resolver'] = $resolver;

        ConfigValidator::validate($config, $this->app);
    }

    /**
     * Run the validator over the package config with the given
     * `resource_tenant_resolver`.
     *
     * @param  mixed  $resolver
     * @return void
     */
    private function validateWithResourceTenantResolver(mixed $resolver): void
    {
        $config                             = $this->authorizationConfig();
        $config['resource_tenant_resolver'] = $resolver;

        ConfigValidator::validate($config, $this->app);
    }

    /**
     * Run the validator over the package config with the given `tenant_tree`.
     *
     * @param  mixed  $tree
     * @return void
     */
    private function validateWithTenantTree(mixed $tree): void
    {
        $config                = $this->authorizationConfig();
        $config['tenant_tree'] = $tree;

        ConfigValidator::validate($config, $this->app);
    }

    /**
     * Run the validator over the package config with the given
     * `permission_enums`.
     *
     * @param  list<string>  $enums
     * @return void
     */
    private function validateWithPermissionEnums(array $enums): void
    {
        $config                     = $this->authorizationConfig();
        $config['permission_enums'] = $enums;

        ConfigValidator::validate($config, $this->app);
    }

    /**
     * Run the validator over the package config with the given `connection`.
     *
     * @param  mixed  $connection
     * @return void
     */
    private function validateWithConnection(mixed $connection): void
    {
        $config               = $this->authorizationConfig();
        $config['connection'] = $connection;

        ConfigValidator::validate($config, $this->app);
    }

    /**
     * Run the validator over the package config with the given `models` block.
     *
     * @param  array<string, mixed>  $models
     * @return void
     */
    private function validateWithModels(array $models): void
    {
        $config           = $this->authorizationConfig();
        $config['models'] = $models;

        ConfigValidator::validate($config, $this->app);
    }

    /**
     * Return the merged package config.
     *
     * @return array<string, mixed>
     */
    private function authorizationConfig(): array
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject

        /** @var array<string, mixed> */
        return (array) $config->get('authorization');
    }

    /**
     * Assert the callback is refused with the given config key and reason.
     *
     * @param  callable(): mixed  $callback
     * @param  string  $key
     * @param  string  $reason
     * @return void
     */
    private function assertRejected(callable $callback, string $key, string $reason): void
    {
        try {
            $callback();
            self::fail('InvalidAuthorizationConfigException was not thrown.');
        } catch (InvalidAuthorizationConfigException $exception) {
            self::assertSame($key, $exception->getConfigKey());
            self::assertSame($reason, $exception->getReason());
        }
    }
}
