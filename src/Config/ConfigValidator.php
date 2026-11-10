<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Config;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authorization\Contracts\PermissionEnum;
use SineMacula\Laravel\Authorization\Contracts\PermissionProvider;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;

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
 * The config must be an array, and it and every block whose keys the package
 * defines may set only those keys (N116), so a misspelt key is refused, naming
 * its full path, rather than leaving its default in place. A key left out takes
 * its default; a key set to null is refused, except where null means off or
 * none: `connection`, `policy_store`, `cache.store`, `usage.connection`,
 * `usage.queue` and `log_channel`. Whole numbers and switches are read as the
 * environment writes them (N117): see `IntegerSetting` and
 * `SwitchConfigValidator`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ConfigValidator
{
    /** @var list<string> The keys the authorization config may set. */
    public const array KEYS = [
        'models', 'connection', 'tables', 'defaults', 'permission_enums', 'permission_providers', 'gate', 'log_channel', 'policy_store',
        'policies', 'query_scoping', 'bulk', 'context', 'attributes', 'subject_resolver', 'tenant_tree', 'identity_directory',
        'application_access', 'resource_tenant_resolver', 'requirement_checker', 'session', 'cache', 'hierarchy', 'rank',
        'administration', 'reviews', 'usage', 'grant_hooks',
    ];

    /** @var array<string, class-string<\Illuminate\Database\Eloquent\Model>> The package model each `models.*` key must be or extend. */
    public const array MODELS = [
        'role'       => Role::class,
        'permission' => Permission::class,
        'policy'     => Policy::class,
    ];

    /**
     * Validate the supplied authorization config. Throws on the first failure
     * encountered — consumers fix one key at a time.
     *
     * @param  mixed  $config
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function validate(mixed $config, Container $container): void
    {
        $root  = ConfigBlock::of('authorization', $config, self::KEYS);
        $given = static fn (string $key, mixed $default = []): mixed => ConfigBlock::entry($root, $key, $default);

        NamedEntryConfigValidator::connection($given('connection', null), $container);
        TableConfigValidator::validate($given('tables'));
        NamedEntryConfigValidator::defaults($given('defaults'), $container);
        NamedEntryConfigValidator::logChannel($given('log_channel', null), $container);
        self::validateModels($given('models'));
        self::permissionEnums($given('permission_enums'));
        self::permissionProviders($given('permission_providers'));
        SeamConfigValidator::validate($root);
        self::validateApplicationAccess($given('application_access'));

        foreach (SwitchConfigValidator::SWITCHES as $switch) {
            SwitchConfigValidator::validate($switch, $given($switch));
        }

        CacheConfigValidator::validate($given('cache'), $container);
        PolicyConfigValidator::validate($given('policies'));
        ContextConfigValidator::validate($given('context'), $container);
        AttributeConfigValidator::validate($given('attributes'), $container);
        SessionConfigValidator::validate($given('session'), $container);
        QueryScopingConfigValidator::validate($given('query_scoping'));
        BulkConfigValidator::validate($given('bulk'));
        AdministrationConfigValidator::validate($given('administration'));
        ReviewConfigValidator::validate($given('reviews'));
        $usage = $given('usage');

        UsageConfigValidator::validate($usage);
        NamedEntryConfigValidator::queueConnection(\is_array($usage) ? ConfigBlock::entry($usage, 'connection', null) : null, $container);
        GrantHookConfigValidator::validate($given('grant_hooks'));
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
    public static function describe(mixed $value): string
    {
        $literal = \is_scalar($value)
            ? \var_export($value, true)
            : \var_export(\get_debug_type($value), true);

        return $literal . ' (' . \get_debug_type($value) . ')';
    }

    /**
     * Determine whether the given value names an enum that implements the
     * `PermissionEnum` contract and is backed by strings: an entry of
     * `permission_enums` the validation accepts.
     *
     * The configuration refuses an entry of `permission_enums` for which this
     * is false.
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
     * Return the entries of `permission_enums`, refusing a value that is not an
     * array, or an entry that is not an enum implementing the `PermissionEnum`
     * contract backed by strings. The permission catalogue reads the list
     * through here at run time, so an entry changed after boot is refused there
     * too, never skipped.
     *
     * @param  mixed  $value
     * @return array<array-key, class-string<\SineMacula\Laravel\Authorization\Contracts\PermissionEnum>>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function permissionEnums(mixed $value): array
    {
        if (!\is_array($value)) {
            throw new InvalidAuthorizationConfigException('authorization.permission_enums', 'expected an array of enum class names, got ' . \get_debug_type($value) . '.');
        }

        foreach ($value as $index => $class) {
            self::validatePermissionEnumEntry($index, $class);
        }

        /** @var array<array-key, class-string<\SineMacula\Laravel\Authorization\Contracts\PermissionEnum>> */
        return $value;
    }

    /**
     * Return the entries of `permission_providers`, refusing a value that is
     * not an array, or an entry that is not a class implementing the
     * `PermissionProvider` contract. The permission catalogue reads the list
     * through here at run time, before it resolves any provider, so an entry
     * changed after boot is refused there too.
     *
     * @param  mixed  $value
     * @return array<array-key, class-string<\SineMacula\Laravel\Authorization\Contracts\PermissionProvider>>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function permissionProviders(mixed $value): array
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

        /** @var array<array-key, class-string<\SineMacula\Laravel\Authorization\Contracts\PermissionProvider>> */
        return $value;
    }

    /**
     * Validate that `models` sets no key but the three models, and that each
     * entry it sets names the package model or a subclass of it. A key left out
     * falls back to the package model, so only the keys present are checked.
     *
     * @param  mixed  $value
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    private static function validateModels(mixed $value): void
    {
        $value = ConfigBlock::of('authorization.models', $value, \array_keys(self::MODELS));

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
}
