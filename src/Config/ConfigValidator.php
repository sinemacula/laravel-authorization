<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Config;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authorization\Contracts\PermissionEnum;
use SineMacula\Laravel\Authorization\Contracts\PermissionProvider;
use SineMacula\Laravel\Authorization\Contracts\PolicyStore;
use SineMacula\Laravel\Authorization\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authorization\Contracts\TenantResolver;
use SineMacula\Laravel\Authorization\Enums\GateConflictMode;
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
        self::validateConnection($config['connection'] ?? null, $container);
        self::validateModels($config['models'] ?? []);
        self::validatePermissionEnums($config['permission_enums'] ?? []);
        self::validatePermissionProviders($config['permission_providers'] ?? []);
        self::validateGateOnConflict($config['gate']['on_conflict'] ?? null);
        self::validatePrincipalResolver($config['principal_resolver'] ?? null);
        self::validateTenantResolver($config['tenant_resolver'] ?? null);
        self::validatePolicyStore($config['policy_store'] ?? null);
        self::validateCacheStore($config['cache']['store'] ?? null, $container);
    }

    /**
     * Determine whether the given value names an enum that implements the
     * `PermissionEnum` contract and is backed by strings: an entry of
     * `permission_enums` the validation accepts.
     *
     * The Gate registrar and the manager read the configured enums at run time,
     * after boot, so they skip an entry for which this is false rather than
     * fail on it.
     *
     * @param  mixed  $class
     * @return bool
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
     * Validate that `gate.on_conflict` is one of the three accepted sentinels
     * backing `GateConflictMode`.
     *
     * @param  mixed  $value
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    private static function validateGateOnConflict(mixed $value): void
    {
        if ($value === null || $value instanceof GateConflictMode) {
            return;
        }

        if (!\is_string($value) || GateConflictMode::tryFrom($value) === null) {
            $accepted = \array_map(
                static fn (GateConflictMode $case): string => "'{$case->value}'",
                GateConflictMode::cases(),
            );

            $reason = 'expected one of [' . \implode(', ', $accepted) . '], got ' . self::describe($value) . '.';

            throw new InvalidAuthorizationConfigException('authorization.gate.on_conflict', $reason);
        }
    }

    /**
     * Validate that `principal_resolver` resolves to a class implementing
     * `PrincipalResolver`.
     *
     * @param  mixed  $value
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    private static function validatePrincipalResolver(mixed $value): void
    {
        if ($value === null) {
            $reason = 'a principal resolver class is required; set it to'
                . ' \SineMacula\Laravel\Authorization\Resolvers\NullPrincipalResolver'
                . ' to keep the package anonymous-safe.';

            throw new InvalidAuthorizationConfigException('authorization.principal_resolver', $reason);
        }

        self::assertImplementsContract(
            $value,
            PrincipalResolver::class,
            'authorization.principal_resolver',
        );
    }

    /**
     * Validate that `tenant_resolver`, when set, resolves to a class
     * implementing `TenantResolver`.
     *
     * @param  mixed  $value
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    private static function validateTenantResolver(mixed $value): void
    {
        if ($value === null) {
            return;
        }

        self::assertImplementsContract(
            $value,
            TenantResolver::class,
            'authorization.tenant_resolver',
        );
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
     * Shared contract-implementation check for `principal_resolver` and
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
