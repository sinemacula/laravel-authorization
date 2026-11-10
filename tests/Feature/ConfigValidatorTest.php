<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Config\ConfigValidator;
use SineMacula\Laravel\Authorization\Contracts\ActionCatalogue;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationRequirementChecker;
use SineMacula\Laravel\Authorization\Contracts\GrantHook;
use SineMacula\Laravel\Authorization\Contracts\IdentityDirectory;
use SineMacula\Laravel\Authorization\Contracts\ResourceTenantResolver;
use SineMacula\Laravel\Authorization\Contracts\SessionPolicySource;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Resolvers\AuthGuardSubjectResolver;
use SineMacula\Laravel\Authorization\Resolvers\FlatTenantTree;
use SineMacula\Laravel\Authorization\Resolvers\GuardUserIdentityDirectory;
use SineMacula\Laravel\Authorization\Resolvers\NoResourceTenant;
use SineMacula\Laravel\Authorization\Resolvers\NoSessionPolicy;
use SineMacula\Laravel\Authorization\Resolvers\RefusingRequirementChecker;
use Tests\Feature\Stubs\ConflictingResourceAttributes;
use Tests\Feature\Stubs\Contracts\PermissionEnumInterface;
use Tests\Feature\Stubs\CustomPermission;
use Tests\Feature\Stubs\CustomPolicy;
use Tests\Feature\Stubs\CustomRole;
use Tests\Feature\Stubs\EmptyActionCatalogue;
use Tests\Feature\Stubs\Enums\IntBackedPermissionEnum;
use Tests\Feature\Stubs\Enums\PermissionEnum;
use Tests\Feature\Stubs\FixedResourceTenantResolver;
use Tests\Feature\Stubs\ReservedContextSource;
use Tests\Feature\Stubs\StubRequirementChecker;
use Tests\Feature\Stubs\StubSubjectResolver;
use Tests\Feature\Stubs\StubTenantTree;
use Tests\Fixtures\GrantScope\ListedIdentityDirectory;
use Tests\TestCase;

/**
 * Feature tests for the boot-time validation of `authorization.models.*`, the
 * connection, the backing of `authorization.permission_enums`, the subject
 * resolver, the tenant tree, the resource tenant resolver, the policy limits,
 * the context and the Gate switch.
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
     * The query scoping limits are validated with the rest: the package's
     * defaults pass, and a limit below 1 is refused under its key.
     *
     * @return void
     */
    public function testQueryScopingLimitsAreValidated(): void
    {
        $config = $this->authorizationConfig();

        self::assertSame(['max_anchors' => 64, 'max_scopes' => 16, 'max_attachments' => 64], $config['query_scoping']);

        ConfigValidator::validate($config, $this->app);

        $config['query_scoping']['max_scopes'] = 0;

        $this->assertRejected(
            fn () => ConfigValidator::validate($config, $this->app),
            'authorization.query_scoping.max_scopes',
            'expected a whole number of at least 1, got 0 (int).',
        );
    }

    /**
     * The bulk check chunk size is validated with the rest: the package's
     * default passes, and a size below 1 is refused under its key.
     *
     * @return void
     */
    public function testTheBulkChunkSizeIsValidated(): void
    {
        $config = $this->authorizationConfig();

        self::assertSame(['chunk_size' => 500], $config['bulk']);

        ConfigValidator::validate($config, $this->app);

        $config['bulk']['chunk_size'] = 0;

        $this->assertRejected(
            fn () => ConfigValidator::validate($config, $this->app),
            'authorization.bulk.chunk_size',
            'expected a whole number of at least 1, got 0 (int).',
        );
    }

    /**
     * The limits of delegated administration are validated with the rest: the
     * package's defaults pass, and an impact limit below 1, or retries below 0,
     * are refused under their key.
     *
     * @return void
     */
    public function testTheAdministrationLimitsAreValidated(): void
    {
        $config = $this->authorizationConfig();

        self::assertSame(['max_impact' => 1000, 'retries' => 2], $config['administration']);

        ConfigValidator::validate($config, $this->app);

        $impact = $config;
        $tries  = $config;

        $impact['administration']['max_impact'] = 0;
        $tries['administration']['retries']     = -1;

        $this->assertRejected(
            fn () => ConfigValidator::validate($impact, $this->app),
            'authorization.administration.max_impact',
            'expected a whole number of at least 1, got 0 (int).',
        );
        $this->assertRejected(
            fn () => ConfigValidator::validate($tries, $this->app),
            'authorization.administration.retries',
            'expected a whole number of at least 0, got -1 (int).',
        );
    }

    /**
     * The access review limit is validated with the rest: the package's default
     * passes, and a limit below 1 or one that is not a whole number is refused
     * under its key, so a review never falls back to another bound.
     *
     * @return void
     */
    public function testTheReviewLimitIsValidated(): void
    {
        $config = $this->authorizationConfig();

        self::assertSame(['limit' => 1000], $config['reviews']);

        ConfigValidator::validate($config, $this->app);

        $zero = $config;
        $text = $config;

        $zero['reviews']['limit'] = 0;
        $text['reviews']['limit'] = '100';

        $this->assertRejected(
            fn () => ConfigValidator::validate($zero, $this->app),
            'authorization.reviews.limit',
            'expected a whole number of at least 1, got 0 (int).',
        );
        $this->assertRejected(
            fn () => ConfigValidator::validate($text, $this->app),
            'authorization.reviews.limit',
            'expected a whole number of at least 1, got \'100\' (string).',
        );
    }

    /**
     * The grant usage block is validated with the rest: the package's default,
     * tracking off, passes, and an interval under a minute is refused under its
     * key.
     *
     * @return void
     */
    public function testTheUsageBlockIsValidated(): void
    {
        $config    = $this->authorizationConfig();
        $container = $this->app;

        self::assertNotNull($container);
        self::assertSame(['enabled' => false, 'interval' => 3600, 'batch' => 250, 'connection' => null, 'queue' => null, 'retention' => 400], $config['usage']);

        ConfigValidator::validate($config, $container);

        $short = $config;

        $short['usage']['interval'] = 59;

        $this->assertRejected(
            static fn () => ConfigValidator::validate($short, $container),
            'authorization.usage.interval',
            'expected a whole number of at least 60, got 59 (int).',
        );
    }

    /**
     * The grant hooks are validated with the rest: the package's default, an
     * empty list, passes, as does a missing key, and a class that is not a hook
     * is refused under its entry's key.
     *
     * @return void
     */
    public function testTheGrantHooksAreValidated(): void
    {
        $config = $this->authorizationConfig();

        self::assertSame([], $config['grant_hooks']);

        ConfigValidator::validate($config, $this->app);

        $missing = $config;

        unset($missing['grant_hooks']);

        ConfigValidator::validate($missing, $this->app);

        $config['grant_hooks'] = [\stdClass::class];

        $this->assertRejected(
            fn () => ConfigValidator::validate($config, $this->app),
            'authorization.grant_hooks.0',
            'class \'stdClass\' does not implement ' . GrantHook::class . '.',
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
     * The shipped refusing checker, any class implementing the contract, and a
     * config without the key pass validation.
     *
     * @return void
     */
    public function testRequirementCheckerImplementingTheContractPasses(): void
    {
        $config = $this->authorizationConfig();

        self::assertSame(RefusingRequirementChecker::class, $config['requirement_checker']);

        foreach ([RefusingRequirementChecker::class, StubRequirementChecker::class] as $checker) {
            ConfigValidator::validate(['requirement_checker' => $checker] + $config, $this->app);
        }

        unset($config['requirement_checker']);

        ConfigValidator::validate($config, $this->app);

        $this->addToAssertionCount(3);
    }

    /**
     * An explicit null, or a class that is no checker, is refused under its
     * key.
     *
     * @return void
     */
    public function testInvalidRequirementCheckerIsRejected(): void
    {
        $config = $this->authorizationConfig();

        $this->assertRejected(
            fn () => ConfigValidator::validate(['requirement_checker' => null] + $config, $this->app),
            'authorization.requirement_checker',
            'a requirement checker class is required; set it to \\' . RefusingRequirementChecker::class . ' to meet no requirement.',
        );
        $this->assertRejected(
            fn () => ConfigValidator::validate(['requirement_checker' => \stdClass::class] + $config, $this->app),
            'authorization.requirement_checker',
            'class \'stdClass\' does not implement ' . AuthenticationRequirementChecker::class . '.',
        );
    }

    /**
     * The shipped identity directory, any class implementing the contract, and
     * a config without the key pass validation.
     *
     * @return void
     */
    public function testIdentityDirectoryImplementingTheContractPasses(): void
    {
        $config = $this->authorizationConfig();

        self::assertSame(GuardUserIdentityDirectory::class, $config['identity_directory']);

        foreach ([GuardUserIdentityDirectory::class, ListedIdentityDirectory::class] as $directory) {
            ConfigValidator::validate(['identity_directory' => $directory] + $config, $this->app);
        }

        unset($config['identity_directory']);

        ConfigValidator::validate($config, $this->app);

        $this->addToAssertionCount(3);
    }

    /**
     * An explicit null, or a class that is no directory, is refused under its
     * key, so no directory never means no principals by accident.
     *
     * @return void
     */
    public function testInvalidIdentityDirectoryIsRejected(): void
    {
        $config = $this->authorizationConfig();

        $this->assertRejected(
            fn () => ConfigValidator::validate(['identity_directory' => null] + $config, $this->app),
            'authorization.identity_directory',
            'an identity directory class is required; set it to \\' . GuardUserIdentityDirectory::class . ' for the default.',
        );
        $this->assertRejected(
            fn () => ConfigValidator::validate(['identity_directory' => \stdClass::class] + $config, $this->app),
            'authorization.identity_directory',
            'class \'stdClass\' does not implement ' . IdentityDirectory::class . '.',
        );
    }

    /**
     * The `session` config is validated with the rest: the shipped source and
     * an empty scope map pass, as does a config without the key, and a source
     * that is no source, or a scope map naming a pattern that covers no
     * declared permission, is refused under its key.
     *
     * @return void
     */
    public function testTheSessionConfigIsValidated(): void
    {
        $config = $this->authorizationConfig();

        self::assertSame(['source' => NoSessionPolicy::class, 'scopes' => []], $config['session']);

        ConfigValidator::validate($config, $this->app);

        unset($config['session']);

        ConfigValidator::validate($config, $this->app);

        $this->assertRejected(
            fn () => ConfigValidator::validate(['session' => ['source' => \stdClass::class]] + $config, $this->app),
            'authorization.session.source',
            'class \'stdClass\' does not implement ' . SessionPolicySource::class . '.',
        );

        $this->app?->instance(ActionCatalogue::class, new EmptyActionCatalogue);

        $this->assertRejected(
            fn () => ConfigValidator::validate(['session' => ['scopes' => ['editor' => ['posts:*']]]] + $config, $this->app),
            'authorization.session.scopes',
            'the scope \'editor\' names \'posts:*\', which covers no declared permission.',
        );
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
     * The shipped `attributes` config passes, and the attribute providers are
     * checked at boot: one declaring a built-in fails it.
     *
     * @return void
     */
    public function testTheAttributesConfigIsValidatedAtBoot(): void
    {
        ConfigValidator::validate($this->authorizationConfig(), $this->app);

        $this->app?->instance(ConflictingResourceAttributes::class, new ConflictingResourceAttributes(['id' => 'string']));

        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.attributes.resources', ['post' => ConflictingResourceAttributes::class]);

        $this->expectException(InvalidAuthorizationConfigException::class);
        $this->expectExceptionMessage('Invalid authorization config at \'authorization.attributes\'');

        (new AuthorizationServiceProvider($this->app))->boot(); // @phpstan-ignore argument.type
    }

    /**
     * The shipped `context` config passes, and the context config is checked at
     * boot: a source claiming a reserved namespace fails it.
     *
     * @return void
     */
    public function testTheContextConfigIsValidatedAtBoot(): void
    {
        ConfigValidator::validate($this->authorizationConfig(), $this->app);

        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.context.sources', [ReservedContextSource::class]);

        $this->assertRejected(
            fn () => (new AuthorizationServiceProvider($this->app))->boot(),
            'authorization.context.sources.0',
            'source \'' . ReservedContextSource::class . '\' supplies the namespace \'request\', which is not a name or is reserved'
                . ' (authentication, request, environment, input, subject, resource).',
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
     * The Gate switch passes when it is true or false, and when the `gate`
     * block or its `enabled` key is left out, which keeps the hook on.
     *
     * @return void
     */
    public function testTheGateSwitchAcceptsOnlyABoolean(): void
    {
        $this->validateWithGate(['enabled' => true]);
        $this->validateWithGate(['enabled' => false]);
        $this->validateWithGate([]);

        $config = $this->authorizationConfig();
        unset($config['gate']);

        ConfigValidator::validate($config, $this->app);

        $this->expectNotToPerformAssertions();
    }

    /**
     * Gate switches that are not strictly true or false, with the description
     * each is refused with.
     *
     * @return iterable<string, array{mixed, string}>
     */
    public static function invalidGateSwitchProvider(): iterable
    {
        yield 'null' => [null, '\'null\' (null)'];
        yield 'zero' => [0, '0 (int)'];
        yield 'one' => [1, '1 (int)'];
        yield 'string false' => ['false', '\'false\' (string)'];
        yield 'string off' => ['off', '\'off\' (string)'];
        yield 'empty string' => ['', '\'\' (string)'];
        yield 'array' => [[true], '\'array\' (array)'];
    }

    /**
     * Any Gate switch that is not strictly true or false is refused rather than
     * read as either, and fails the provider's boot.
     *
     * @param  mixed  $enabled
     * @param  string  $described
     * @return void
     */
    #[DataProvider('invalidGateSwitchProvider')]
    public function testAGateSwitchThatIsNotABooleanIsRejected(mixed $enabled, string $described): void
    {
        $reason = "expected true or false, got {$described}.";

        $this->assertRejected(fn () => $this->validateWithGate(['enabled' => $enabled]), 'authorization.gate.enabled', $reason);

        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.gate.enabled', $enabled);

        $this->assertRejected(fn () => (new AuthorizationServiceProvider($this->app))->boot(), 'authorization.gate.enabled', $reason);
    }

    /**
     * A `gate` block that is not an array is refused.
     *
     * @return void
     */
    public function testANonArrayGateBlockIsRejected(): void
    {
        $this->assertRejected(fn () => $this->validateWithGate(false), 'authorization.gate', 'expected an array, got false (bool).');
        $this->assertRejected(fn () => $this->validateWithGate(null), 'authorization.gate', 'expected an array, got \'null\' (null).');
    }

    /**
     * Run the validator over the package config with the given `gate` block.
     *
     * @param  mixed  $gate
     * @return void
     */
    private function validateWithGate(mixed $gate): void
    {
        $config         = $this->authorizationConfig();
        $config['gate'] = $gate;

        ConfigValidator::validate($config, $this->app);
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
