<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Config;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authorization\Contracts\IdentityDirectory;
use SineMacula\Laravel\Authorization\Contracts\PermissionEnum;
use SineMacula\Laravel\Authorization\Contracts\PermissionProvider;
use SineMacula\Laravel\Authorization\Contracts\PolicyStore;
use SineMacula\Laravel\Authorization\Contracts\ResourceTenantResolver;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Evaluation\PolicyLimits;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Resolvers\AuthGuardSubjectResolver;
use SineMacula\Laravel\Authorization\Resolvers\FlatTenantTree;
use SineMacula\Laravel\Authorization\Resolvers\GuardUserIdentityDirectory;
use SineMacula\Laravel\Authorization\Resolvers\NoResourceTenant;
use SineMacula\Laravel\Authorization\Resolvers\RefusingRequirementChecker;

/**
 * Boot-time validator for the shipped authorization config.
 *
 * Runs from the service provider's boot phase (after every package has had a
 * chance to register its bindings) so the failure mode is a clear typed
 * exception on container boot rather than a deep stack trace from the first
 * `can()` call in production. Each accepted config key is validated against the
 * concrete contract it must satisfy; the thrown
 * `InvalidAuthorizationConfigException` carries the offending key and a
 * human-readable reason.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ConfigValidator
{
    /** @var array<string, class-string<\Illuminate\Database\Eloquent\Model>> The package model each `models.*` key must be or extend. */
    private const array MODELS = [
        'role'       => Role::class,
        'permission' => Permission::class,
        'policy'     => Policy::class,
    ];

    /**
     * Validate the supplied authorization config. Throws on the first failure
     * encountered — consumers fix one key at a time.
     *
     * @param  array<string, mixed>  $config
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function validate(array $config, Container $container): void
    {
        // A key holding null reads as its default, except where only a missing
        // key does, so that a null set on purpose is validated as given.
        $value = static fn (string $key, mixed $default = null): mixed => $config[$key] ?? $default;
        $given = static fn (string $key, mixed $default): mixed => \array_key_exists($key, $config) ? $config[$key] : $default;

        self::validateConnection($value('connection'), $container);
        self::validateModels($value('models', []));
        self::validatePermissionEnums($value('permission_enums', []));
        self::validatePermissionProviders($value('permission_providers', []));
        self::validateGate($given('gate', []));
        self::validateSubjectResolver($value('subject_resolver'));
        self::validateTenantTree($value('tenant_tree'));
        ImplementationConfigValidator::validate(
            'authorization.identity_directory',
            $given('identity_directory', GuardUserIdentityDirectory::class),
            IdentityDirectory::class,
            'an identity directory class is required; set it to \\' . GuardUserIdentityDirectory::class . ' for the default.',
        );
        self::validateApplicationAccess($value('application_access', []));
        self::validateResourceTenantResolver($value('resource_tenant_resolver'));
        RequirementCheckerConfigValidator::validate($given('requirement_checker', RefusingRequirementChecker::class));
        self::validatePolicyStore($value('policy_store'));
        self::validateCacheStore($config['cache']['store'] ?? null, $container);
        self::validateCacheTtl($config['cache']['ttl'] ?? 300);
        self::validatePolicyLimits($config['policies']['limits'] ?? []);
        ContextConfigValidator::validate($value('context', []), $container);
        AttributeConfigValidator::validate($value('attributes', []), $container);
        SessionConfigValidator::validate($value('session', []), $container);
        QueryScopingConfigValidator::validate($value('query_scoping', []));
        BulkConfigValidator::validate($value('bulk', []));
        AdministrationConfigValidator::validate($value('administration', []));
        ReviewConfigValidator::validate($value('reviews', []));
        UsageConfigValidator::validateIn($config);
        GrantHookConfigValidator::validate($given('grant_hooks', []));
    }

    /**
     * Determine whether the given value names an enum that implements the
     * `PermissionEnum` contract and is backed by strings: an entry of
     * `permission_enums` the validation accepts.
     *
     * The permission catalogue reads the configured enums at run time, after
     * boot, so it skips an entry for which this is false rather than fail on
     * it.
     *
     * @param  mixed  $class
     * @return bool
     *
     * @phpstan-assert-if-true class-string<\SineMacula\Laravel\Authorization\Contracts\PermissionEnum> $class
     */
    public static function isStringBackedPermissionEnum(mixed $class): bool
    {
        return \is_string($class)
            && \is_subclass_of($class, PermissionEnum::class)
            && self::isStringBackedEnum($class);
    }

    /**
     * Validate that `connection`, when set, names a connection the application
     * configures under `database.connections`. Null or an empty name selects
     * the application's default connection.
     *
     * @param  mixed  $value
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    private static function validateConnection(mixed $value, Container $container): void
    {
        if ($value === null || $value === '') {
            return;
        }

        if (!\is_string($value)) {
            throw new InvalidAuthorizationConfigException('authorization.connection', 'expected a database connection name, got ' . self::describe($value) . '.');
        }

        /** @var \Illuminate\Config\Repository $config */
        $config = $container->make('config');

        if (!\is_array($config->get('database.connections.' . $value))) {
            throw new InvalidAuthorizationConfigException('authorization.connection', "database connection '{$value}' is not configured.");
        }
    }

    /**
     * Validate that every configured `models.*` entry names the package model
     * or a subclass of it. A key left out falls back to the package model, so
     * only the keys present are checked.
     *
     * @param  mixed  $value
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    private static function validateModels(mixed $value): void
    {
        if (!\is_array($value)) {
            throw new InvalidAuthorizationConfigException('authorization.models', 'expected an array of model class names, got ' . self::describe($value) . '.');
        }

        foreach (self::MODELS as $key => $base) {
            if (!\array_key_exists($key, $value)) {
                continue;
            }

            self::validateModelEntry("authorization.models.{$key}", $value[$key], $base);
        }
    }

    /**
     * Validate that a single `models.*` entry is an existing class that is the
     * supplied package model or extends it.
     *
     * @param  string  $configKey
     * @param  mixed  $class
     * @param  class-string<\Illuminate\Database\Eloquent\Model>  $base
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    private static function validateModelEntry(string $configKey, mixed $class, string $base): void
    {
        if (!\is_string($class) || $class === '') {
            throw new InvalidAuthorizationConfigException($configKey, 'expected a class-string, got ' . self::describe($class) . '.');
        }

        if (!\class_exists($class)) {
            throw new InvalidAuthorizationConfigException($configKey, "class '{$class}' does not exist.");
        }

        if (!\is_a($class, $base, allow_string: true)) {
            throw new InvalidAuthorizationConfigException($configKey, "class '{$class}' is neither {$base} nor a subclass of it.");
        }
    }

    /**
     * Validate that every entry in `permission_enums` resolves to a class
     * implementing the `PermissionEnum` contract.
     *
     * @param  mixed  $value
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    private static function validatePermissionEnums(mixed $value): void
    {
        if (!\is_array($value)) {
            throw new InvalidAuthorizationConfigException('authorization.permission_enums', 'expected an array of enum class names, got ' . \get_debug_type($value) . '.');
        }

        foreach ($value as $index => $class) {
            self::validatePermissionEnumEntry($index, $class);
        }
    }

    /**
     * Validate a single `permission_enums` entry resolves to an existing enum
     * implementing the `PermissionEnum` contract and backed by strings, since a
     * case's value is the permission name.
     *
     * @param  int|string  $index
     * @param  mixed  $class
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    private static function validatePermissionEnumEntry(int|string $index, mixed $class): void
    {
        if (!\is_string($class) || $class === '') {
            throw new InvalidAuthorizationConfigException("authorization.permission_enums.{$index}", 'entry must be a non-empty class-string.');
        }

        if (!\class_exists($class) && !\interface_exists($class) && !\enum_exists($class)) {
            throw new InvalidAuthorizationConfigException("authorization.permission_enums.{$index}", "class '{$class}' does not exist.");
        }

        if (!\is_subclass_of($class, PermissionEnum::class)) {
            throw new InvalidAuthorizationConfigException("authorization.permission_enums.{$index}", "class '{$class}' does not implement " . PermissionEnum::class . '.');
        }

        if (!self::isStringBackedEnum($class)) {
            $reason = "enum '{$class}' must be backed by strings, since each case's value is a permission name.";

            throw new InvalidAuthorizationConfigException("authorization.permission_enums.{$index}", $reason);
        }
    }

    /**
     * Determine whether the given type is an enum backed by strings. An
     * interface extending the contract is not an enum.
     *
     * @param  string  $class
     * @return bool
     */
    private static function isStringBackedEnum(string $class): bool
    {
        return \enum_exists($class)
            && (string) (new \ReflectionEnum($class))->getBackingType() === 'string';
    }

    /**
     * Validate that every entry in `permission_providers` resolves to a class
     * implementing the `PermissionProvider` contract.
     *
     * @param  mixed  $value
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    private static function validatePermissionProviders(mixed $value): void
    {
        if (!\is_array($value)) {
            throw new InvalidAuthorizationConfigException('authorization.permission_providers', 'expected an array of class names, got ' . \get_debug_type($value) . '.');
        }

        foreach ($value as $index => $class) {
            if (!\is_string($class) || $class === '') {
                throw new InvalidAuthorizationConfigException("authorization.permission_providers.{$index}", 'entry must be a non-empty class-string.');
            }

            if (!\class_exists($class)) {
                throw new InvalidAuthorizationConfigException("authorization.permission_providers.{$index}", "class '{$class}' does not exist.");
            }

            if (!\is_subclass_of($class, PermissionProvider::class)) {
                $reason = "class '{$class}' does not implement " . PermissionProvider::class . '.';

                throw new InvalidAuthorizationConfigException("authorization.permission_providers.{$index}", $reason);
            }
        }
    }

    /**
     * Validate that `gate` is an array whose `enabled` switch, when present, is
     * strictly true or false. Anything else, `null`, `0`, `'false'` or `'off'`
     * among it, is refused rather than read as either, since it decides whether
     * the package answers the Gate at all.
     *
     * @param  mixed  $value
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    private static function validateGate(mixed $value): void
    {
        if (!\is_array($value)) {
            throw new InvalidAuthorizationConfigException('authorization.gate', 'expected an array, got ' . self::describe($value) . '.');
        }

        if (\array_key_exists('enabled', $value) && !\is_bool($value['enabled'])) {
            throw new InvalidAuthorizationConfigException('authorization.gate.enabled', 'expected true or false, got ' . self::describe($value['enabled']) . '.');
        }
    }

    /**
     * Validate that `subject_resolver` resolves to a class implementing
     * `SubjectResolver`. Null is refused rather than read as "no subject", so a
     * missing resolver fails at boot instead of changing who checks are about.
     *
     * @param  mixed  $value
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    private static function validateSubjectResolver(mixed $value): void
    {
        if ($value === null) {
            $reason = 'a subject resolver class is required; set it to \\' . AuthGuardSubjectResolver::class
                . ' to decide about the user Laravel authenticated.';

            throw new InvalidAuthorizationConfigException('authorization.subject_resolver', $reason);
        }

        self::assertImplementsContract(
            $value,
            SubjectResolver::class,
            'authorization.subject_resolver',
        );
    }

    /**
     * Validate that `tenant_tree` resolves to a class implementing
     * `TenantTree`. Null is refused rather than read as a flat tree, so a
     * missing tree fails at boot instead of changing where grants apply.
     *
     * @param  mixed  $value
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    private static function validateTenantTree(mixed $value): void
    {
        if ($value === null) {
            $reason = 'a tenant tree class is required; set it to \\' . FlatTenantTree::class . ' for a flat set of tenants.';

            throw new InvalidAuthorizationConfigException('authorization.tenant_tree', $reason);
        }

        self::assertImplementsContract($value, TenantTree::class, 'authorization.tenant_tree');
    }

    /**
     * Validate that `application_access` maps application names to the
     * permission names they require, each a non-empty string.
     *
     * @param  mixed  $value
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    private static function validateApplicationAccess(mixed $value): void
    {
        if (!\is_array($value)) {
            throw new InvalidAuthorizationConfigException('authorization.application_access', 'expected an array of application names to permission names.');
        }

        foreach ($value as $application => $permission) {
            if (!\is_string($application) || $application === '' || !\is_string($permission) || $permission === '') {
                throw new InvalidAuthorizationConfigException('authorization.application_access', 'each application name must map to a permission name, both non-empty strings.');
            }
        }
    }

    /**
     * Validate that `resource_tenant_resolver` resolves to a class implementing
     * `ResourceTenantResolver`. Null is refused rather than read as no tenant,
     * so a missing resolver fails at boot.
     *
     * @param  mixed  $value
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    private static function validateResourceTenantResolver(mixed $value): void
    {
        if ($value === null) {
            $reason = 'a resource tenant resolver class is required; set it to \\' . NoResourceTenant::class . ' to read no resource\'s tenant.';

            throw new InvalidAuthorizationConfigException('authorization.resource_tenant_resolver', $reason);
        }

        self::assertImplementsContract($value, ResourceTenantResolver::class, 'authorization.resource_tenant_resolver');
    }

    /**
     * Validate that `policy_store`, when set, resolves to a class implementing
     * `PolicyStore`.
     *
     * @param  mixed  $value
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    private static function validatePolicyStore(mixed $value): void
    {
        if ($value === null) {
            return;
        }

        self::assertImplementsContract(
            $value,
            PolicyStore::class,
            'authorization.policy_store',
        );
    }

    /**
     * Validate that `cache.store`, when set, resolves through the Laravel cache
     * manager. Uses a try/catch because the cache manager throws
     * `InvalidArgumentException` on an unknown store name — we swap that for
     * the typed config exception.
     *
     * @param  mixed  $value
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    private static function validateCacheStore(mixed $value, Container $container): void
    {
        if ($value === null) {
            return;
        }

        if (!\is_string($value) || $value === '') {
            throw new InvalidAuthorizationConfigException('authorization.cache.store', 'expected a cache-store name string, got ' . self::describe($value) . '.');
        }

        if (!$container->bound('cache')) {
            return;
        }

        try {
            $container->make('cache')->store($value);
        } catch (\Throwable $exception) {
            throw new InvalidAuthorizationConfigException('authorization.cache.store', "cache store '{$value}' is not configured: " . $exception->getMessage());
        }
    }

    /**
     * Validate that `cache.ttl`, the longest an entry lives, is a whole number
     * of seconds of at least 1. There is no "forever": an entry that missed an
     * invalidation would otherwise never heal.
     *
     * @param  mixed  $value
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    private static function validateCacheTtl(mixed $value): void
    {
        if (\is_int($value) && $value >= 1) {
            return;
        }

        throw new InvalidAuthorizationConfigException('authorization.cache.ttl', 'expected a whole number of seconds of at least 1, got ' . self::describe($value) . '.');
    }

    /**
     * Validate that `policies.limits` is an array, and that each limit it sets
     * is a whole number of at least 1. A limit it does not set takes its
     * default.
     *
     * @param  mixed  $value
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    private static function validatePolicyLimits(mixed $value): void
    {
        if (!\is_array($value)) {
            throw new InvalidAuthorizationConfigException('authorization.policies.limits', 'expected an array of limits, got ' . self::describe($value) . '.');
        }

        foreach (PolicyLimits::KEYS as $key) {
            if (!isset($value[$key])) {
                continue;
            }

            $limit = $value[$key];

            if (!\is_int($limit) || $limit < 1) {
                throw new InvalidAuthorizationConfigException("authorization.policies.limits.{$key}", 'expected a whole number of at least 1, got ' . self::describe($limit) . '.');
            }
        }
    }

    /**
     * Shared contract-implementation check for `subject_resolver` and
     * `policy_store`.
     *
     * @param  mixed  $value
     * @param  class-string  $contract
     * @param  string  $configKey
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    private static function assertImplementsContract(mixed $value, string $contract, string $configKey): void
    {
        if (!\is_string($value) || $value === '') {
            throw new InvalidAuthorizationConfigException($configKey, 'expected a class-string, got ' . self::describe($value) . '.');
        }

        if (!\class_exists($value)) {
            throw new InvalidAuthorizationConfigException($configKey, "class '{$value}' does not exist.");
        }

        if (!\is_subclass_of($value, $contract) && !\is_a($value, $contract, allow_string: true)) {
            throw new InvalidAuthorizationConfigException($configKey, "class '{$value}' does not implement {$contract}.");
        }
    }

    /**
     * Render a short debug description of a mixed value for use inside
     * exception messages.
     *
     * Every value — scalar or otherwise — is rendered in the same shape: the
     * literal followed by the parenthesised debug type. Operators grepping
     * production logs for misconfiguration get predictable output regardless of
     * the value's runtime type.
     *
     * @param  mixed  $value
     * @return string
     */
    private static function describe(mixed $value): string
    {
        $literal = \is_scalar($value)
            ? \var_export($value, true)
            : \var_export(\get_debug_type($value), true);

        return $literal . ' (' . \get_debug_type($value) . ')';
    }
}
