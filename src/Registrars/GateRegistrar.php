<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Registrars;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Gate;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableResource;
use SineMacula\Laravel\Authorization\Contracts\PermissionEnum;
use SineMacula\Laravel\Authorization\Enums\GateConflictMode;
use SineMacula\Laravel\Authorization\Exceptions\GateConflictException;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Support\AuthorizationLog;

/**
 * Walk every configured permission enum and register a matching Laravel Gate.
 * With no enums configured the registrar is a no-op and the Gate surface stays
 * silent; the `Authorization` facade continues to work.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class GateRegistrar
{
    /**
     * Create a new registrar instance.
     *
     * @param  \Illuminate\Contracts\Foundation\Application  $app
     */
    public function __construct(

        /** Framework container consulted for config and bindings. */
        private Application $app,
    ) {}

    /**
     * Walk every configured permission enum and register a Gate per case.
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
     * Resolve the configured gate-conflict mode, defaulting to `THROW` when the
     * raw value is missing or malformed.
     *
     * @return \SineMacula\Laravel\Authorization\Enums\GateConflictMode
     */
    private function resolveConflictMode(): GateConflictMode
    {
        /** @var mixed $rawMode */
        $rawMode = $this->app['config']->get('authorization.gate.on_conflict', GateConflictMode::THROW->value);

        return match (true) {
            $rawMode instanceof GateConflictMode => $rawMode,
            \is_string($rawMode)                 => GateConflictMode::tryFrom($rawMode) ?? GateConflictMode::THROW,
            default                              => GateConflictMode::THROW,
        };
    }

    /**
     * Register a single Gate for the supplied enum case, honouring the
     * configured conflict mode.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\PermissionEnum  $case
     * @param  \SineMacula\Laravel\Authorization\Enums\GateConflictMode  $onConflict
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\GateConflictException
     */
    private function registerEnumGate(PermissionEnum $case, GateConflictMode $onConflict): void
    {
        // The config validation refuses an enum not backed by strings at boot.
        /** @var string $permission */
        $permission = $case->value;

        if (Gate::has($permission)) {
            // Exhaustive match over GateConflictMode: Throw short-circuits,
            // Overwrite falls through to redefine, Log records and bails.
            $shouldDefine = match ($onConflict) {
                GateConflictMode::THROW     => throw new GateConflictException($permission),
                GateConflictMode::OVERWRITE => true,
                GateConflictMode::LOG       => (function () use ($permission): bool {
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

                /** @var \SineMacula\Laravel\Authorization\AuthorizationManager $manager */
                $manager = $user === null ? Authorization::getFacadeRoot() : Authorization::for($user);

                // An argument the evaluator cannot identify as a resource
                // denies, rather than turning the check into one about no
                // resource at all.
                return $resource === false
                    ? $manager->refuseUnidentifiedResource($permission, $context)->allowed
                    : $manager->can($permission, $resource, $context);
            },
        );
    }

    /**
     * Translate the arguments Laravel hands to a Gate callback into the
     * `(resource, context)` pair the authorization manager accepts. Positional
     * entries map to the resource identifier; string keys and string-keyed
     * arrays merge into the context map. The resource is false when the first
     * positional argument cannot be identified as a resource.
     *
     * @param  array<int|string, mixed>  $arguments
     * @return array{0: false|string|null, 1: array<string, mixed>}
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

            [$resource, $context] = self::applyPositionalGateArgument($key, $value, $resource, $context);
        }

        return [$resource, $context];
    }

    /**
     * Fold a positional Gate-callback argument into the resource / context
     * pair. Index zero may carry either the resource identifier or an
     * associative context map; later positions only merge associative maps.
     *
     * @param  int  $key
     * @param  mixed  $value
     * @param  false|string|null  $resource
     * @param  array<string, mixed>  $context
     * @return array{0: false|string|null, 1: array<string, mixed>}
     */
    private static function applyPositionalGateArgument(int $key, mixed $value, false|string|null $resource, array $context): array
    {
        $isContextMap = \is_array($value) && !\array_is_list($value);

        if ($key === 0 && !$isContextMap) {
            return [self::stringifyGateResource($value), $context];
        }

        if (!$isContextMap) {
            return [$resource, $context];
        }

        /** @var array<string, mixed> $value */
        return [$resource, \array_merge($context, $value)];
    }

    /**
     * Coerce a Gate-callback argument into a resource identifier string.
     *
     * Returns null for a null argument (no resource) and false for a value the
     * evaluator cannot identify, such as an unsaved model, a number or a list,
     * so the check denies instead of matching every resource-less statement.
     * The resource contract wins over a model's own identifier.
     *
     * @param  mixed  $value
     * @return false|string|null
     */
    private static function stringifyGateResource(mixed $value): false|string|null
    {
        return match (true) {
            $value === null                                            => null,
            $value instanceof AuthorizableResource                     => $value->toResourceIdentifier(),
            $value instanceof Model                                    => self::modelIdentifier($value),
            \is_string($value)                                         => $value,
            \is_object($value) && \method_exists($value, '__toString') => (string) $value,
            default                                                    => false,
        };
    }

    /**
     * Identify a model as `morphClass:key`, or false when it has no usable key
     * (an unsaved model).
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return false|string
     */
    private static function modelIdentifier(Model $model): false|string
    {
        $key = $model->getKey();

        return \is_scalar($key) && $key !== '' ? $model->getMorphClass() . ':' . $key : false;
    }

    /**
     * Emit the configured conflict warning.
     *
     * @param  string  $permission
     * @return void
     */
    private function logGateConflict(string $permission): void
    {
        AuthorizationLog::warning("Authorization gate '{$permission}' already registered; existing Gate preserved.");
    }
}
