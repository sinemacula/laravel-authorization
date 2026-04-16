<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Config;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authorization\Contracts\PermissionEnum;
use SineMacula\Laravel\Authorization\Contracts\PolicyStore;
use SineMacula\Laravel\Authorization\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authorization\Enums\GateConflictMode;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;

/**
 * Boot-time validator for the shipped authorization config.
 *
 * Runs from the service provider's boot phase (after every package
 * has had a chance to register its bindings) so the failure mode
 * is a clear typed exception on container boot rather than a deep
 * stack trace from the first `can()` call in production. Each
 * accepted config key is validated against the concrete contract
 * it must satisfy; the thrown
 * `InvalidAuthorizationConfigException` carries the offending
 * key and a human-readable reason.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ConfigValidator
{
    /**
     * Validate the supplied authorization config. Throws on the
     * first failure encountered — consumers fix one key at a time.
     *
     * @param  array<string, mixed>  $config
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function validate(array $config, Container $container): void
    {
        self::validatePermissionEnums($config['permission_enums'] ?? []);
        self::validateGateOnConflict($config['gate']['on_conflict'] ?? null);
        self::validatePrincipalResolver($config['principal_resolver'] ?? null);
        self::validatePolicyStore($config['policy_store'] ?? null);
        self::validateCacheStore($config['cache']['store'] ?? null, $container);
    }

    /**
     * Validate that every entry in `permission_enums` resolves to
     * a class implementing the `PermissionEnum` contract.
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
            if (!\is_string($class) || $class === '') {
                throw new InvalidAuthorizationConfigException("authorization.permission_enums.{$index}", 'entry must be a non-empty class-string.');
            }

            if (!\class_exists($class) && !\interface_exists($class) && !\enum_exists($class)) {
                throw new InvalidAuthorizationConfigException("authorization.permission_enums.{$index}", "class '{$class}' does not exist.");
            }

            if (!\is_subclass_of($class, PermissionEnum::class)) {
                throw new InvalidAuthorizationConfigException("authorization.permission_enums.{$index}", "class '{$class}' does not implement " . PermissionEnum::class . '.');
            }
        }
    }

    /**
     * Validate that `gate.on_conflict` is one of the three accepted
     * sentinels backing `GateConflictMode`.
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

            throw new InvalidAuthorizationConfigException('authorization.gate.on_conflict', 'expected one of [' . \implode(', ', $accepted) . '], got ' . self::describe($value) . '.');
        }
    }

    /**
     * Validate that `principal_resolver` resolves to a class
     * implementing `PrincipalResolver`.
     *
     * @param  mixed  $value
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    private static function validatePrincipalResolver(mixed $value): void
    {
        if ($value === null) {
            throw new InvalidAuthorizationConfigException('authorization.principal_resolver', 'a principal resolver class is required; set it to \SineMacula\Laravel\Authorization\Resolvers\NullPrincipalResolver to keep the package anonymous-safe.');
        }

        self::assertImplementsContract(
            $value,
            PrincipalResolver::class,
            'authorization.principal_resolver',
        );
    }

    /**
     * Validate that `policy_store`, when set, resolves to a class
     * implementing `PolicyStore`.
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
     * Validate that `cache.store`, when set, resolves through the
     * Laravel cache manager. Uses a try/catch because the cache
     * manager throws `InvalidArgumentException` on an unknown
     * store name — we swap that for the typed config exception.
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
     * Shared contract-implementation check for
     * `principal_resolver` and `policy_store`.
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
     * Render a short debug description of a mixed value for use
     * inside exception messages.
     *
     * Every value — scalar or otherwise — is rendered in the same
     * shape: the literal followed by the parenthesised debug type.
     * Operators grepping production logs for misconfiguration get
     * predictable output regardless of the value's runtime type
     * (see issue #74).
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
