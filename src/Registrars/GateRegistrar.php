<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Registrars;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Log;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableResource;
use SineMacula\Laravel\Authorization\Contracts\PermissionEnum;
use SineMacula\Laravel\Authorization\Enums\GateConflictMode;
use SineMacula\Laravel\Authorization\Exceptions\GateConflictException;
use SineMacula\Laravel\Authorization\Facades\Authorization;

/**
 * Walk every configured permission enum and register a matching
 * Laravel Gate.
 *
 * Laravel's Gate never dispatches to an action it has not been told
 * about, so an empty `authorization.permission_enums` config leaves
 * `Gate::allows(...)`, `$user->can(...)`, `@can(...)`, and the
 * `can:` middleware silent — they return false for every action.
 * The `Authorization` facade still works out of the box; the Gate
 * surface only lights up once a `PermissionEnum` is registered
 * here. Consumers using the facade exclusively can leave the
 * config empty and this registrar is a no-op.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class GateRegistrar
{
    /**
     * Create a new registrar instance.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     */
    public function __construct(

        /** Framework container consulted for config and bindings. */
        private readonly Application $app,

    ) {}

    /**
     * Walk every configured permission enum and register a Gate per
     * case.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\GateConflictException
     */
    public function register(): void
    {
        /** @var array<int, mixed> $enums */
        $enums = $this->app['config']->get('authorization.permission_enums', []);

        $onConflict = $this->resolveConflictMode();

        foreach ($enums as $enumClass) {
            if (!\is_string($enumClass) || !\is_subclass_of($enumClass, PermissionEnum::class)) {
                continue;
            }

            /** @var class-string<\SineMacula\Laravel\Authorization\Contracts\PermissionEnum> $className */
            $className = $enumClass;

            foreach ($className::cases() as $case) {
                $this->registerEnumGate($case, $onConflict);
            }
        }
    }

    /**
     * Resolve the configured gate-conflict mode, defaulting to
     * `THROW` when the raw value is missing or malformed.
     *
     * @return \SineMacula\Laravel\Authorization\Enums\GateConflictMode
     */
    private function resolveConflictMode(): GateConflictMode
    {
        /** @var mixed $rawMode */
        $rawMode = $this->app['config']->get('authorization.gate.on_conflict', GateConflictMode::Throw->value);

        return match (true) {
            $rawMode instanceof GateConflictMode => $rawMode,
            \is_string($rawMode)                 => GateConflictMode::tryFrom($rawMode) ?? GateConflictMode::Throw,
            default                              => GateConflictMode::Throw,
        };
    }

    /**
     * Register a single Gate for the supplied enum case, honouring
     * the configured conflict mode.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\PermissionEnum  $case
     * @param  \SineMacula\Laravel\Authorization\Enums\GateConflictMode  $onConflict
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\GateConflictException
     */
    private function registerEnumGate(PermissionEnum $case, GateConflictMode $onConflict): void
    {
        $permission = $case->toString();

        if (Gate::has($permission)) {
            // Exhaustive match over GateConflictMode: Throw short-circuits,
            // Overwrite falls through to redefine, Log records and bails.
            $shouldDefine = match ($onConflict) {
                GateConflictMode::Throw     => throw new GateConflictException($permission),
                GateConflictMode::Overwrite => true,
                GateConflictMode::Log       => (function () use ($permission): bool {
                    $this->logGateConflict($permission);

                    return false;
                })(),
            };

            if (!$shouldDefine) {
                return;
            }
        }

        Gate::define(
            $permission,
            static function (?object $user = null, mixed ...$arguments) use ($permission): bool {
                [$resource, $context] = self::translateGateArguments($arguments);

                if ($user === null) {
                    return Authorization::can($permission, $resource, $context);
                }

                return Authorization::for($user)->can($permission, $resource, $context);
            },
        );
    }

    /**
     * Translate the arguments Laravel hands to a Gate callback into
     * the `(resource, context)` pair the authorization manager
     * accepts.
     *
     * Laravel's Gate spreads the argument tail into the callback
     * with PHP's `...` operator, so an associative array ends up in
     * the variadic parameter under its original string keys rather
     * than at numeric index 0. The translation treats positional
     * entries (integer keys) and named entries (string keys)
     * separately:
     *
     * - The first positional argument is the resource identifier.
     *   Strings pass through unchanged, Eloquent models become
     *   `{morphClass}:{key}` (matching the polymorphic pivots'
     *   convention — register a morph alias on the consumer side
     *   to avoid FQN backslashes leaking into resource strings),
     *   stringable objects are cast via `__toString`, and anything
     *   else yields a null resource.
     * - A positional array at index 0 that is string-keyed is
     *   treated as a context map with no resource, covering the
     *   `Gate::allows('edit', ['tenant' => '…'])` idiom.
     * - Any string-keyed array found after the resource slot is
     *   merged into the context. String-keyed entries in the
     *   variadic itself (PHP spread of an assoc array) flow
     *   directly into the context.
     * - Unmappable trailing positional values are discarded rather
     *   than guessed at.
     *
     * @param  array<int|string, mixed>  $arguments
     * @return array{0: string|null, 1: array<string, mixed>}
     */
    private static function translateGateArguments(array $arguments): array
    {
        if ($arguments === []) {
            return [null, []];
        }

        $resource = null;
        $context  = [];

        foreach ($arguments as $key => $value) {
            if (\is_string($key)) {
                $context[$key] = $value;

                continue;
            }

            if ($key === 0) {
                if (\is_array($value) && !\array_is_list($value)) {
                    /** @var array<string, mixed> $value */
                    $context = \array_merge($context, $value);
                } else {
                    $resource = self::stringifyGateResource($value);
                }

                continue;
            }

            if (\is_array($value) && !\array_is_list($value)) {
                /** @var array<string, mixed> $value */
                $context = \array_merge($context, $value);
            }
        }

        return [$resource, $context];
    }

    /**
     * Coerce a Gate-callback argument into a resource identifier
     * string. Returns null when the value is not a resource the
     * evaluator can reason about.
     *
     * @param  mixed  $value
     * @return string|null
     */
    private static function stringifyGateResource(mixed $value): ?string
    {
        if ($value instanceof Model) {
            $key = $value->getKey();

            return \is_scalar($key) ? $value->getMorphClass() . ':' . (string) $key : null;
        }

        return match (true) {
            \is_string($value)                                         => $value,
            $value instanceof AuthorizableResource                     => $value->toResourceIdentifier(),
            \is_object($value) && \method_exists($value, '__toString') => (string) $value,
            default                                                    => null,
        };
    }

    /**
     * Emit the configured conflict warning.
     *
     * @param  string  $permission
     * @return void
     */
    private function logGateConflict(string $permission): void
    {
        try {
            Log::channel('authorization')->warning(
                "Authorization gate '{$permission}' already registered; existing Gate preserved.",
            );
        } catch (\Throwable) {
            Log::warning(
                "Authorization gate '{$permission}' already registered; existing Gate preserved.",
            );
        }
    }
}
