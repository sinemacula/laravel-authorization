<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Registrars;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Facades\Gate;
use SineMacula\Laravel\Authorization\Config\ConfigValidator;
use SineMacula\Laravel\Authorization\Contracts\PermissionEnum;
use SineMacula\Laravel\Authorization\Enums\GateConflictMode;
use SineMacula\Laravel\Authorization\Exceptions\GateConflictException;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Support\AuthorizationLog;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use SineMacula\Laravel\Authorization\Support\ResourceReferences;

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
            if (!ConfigValidator::isStringBackedPermissionEnum($enumClass)) {
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
        // register() skips an enum not backed by strings.
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

                // The subject resolver translates the Gate's user into the
                // subject; with no user, the request's own subject decides.
                /** @var \SineMacula\Laravel\Authorization\AuthorizationManager $manager */
                $manager = $user === null ? Authorization::getFacadeRoot() : Authorization::forUser($user);

                // An argument that cannot be identified as a resource denies as
                // `resource_unresolved`, rather than turning the check into one
                // about no resource at all.
                return $manager->can($permission, $resource, $context);
            },
        );
    }

    /**
     * Translate the arguments Laravel hands to a Gate callback into the
     * `(resource, context)` pair the authorization manager accepts. Positional
     * entries map to the resource reference; string keys and string-keyed
     * arrays merge into the context map. The resource is false when the first
     * positional argument cannot be identified as a resource.
     *
     * @param  array<int|string, mixed>  $arguments
     * @return array{0: false|\SineMacula\Laravel\Authorization\Support\ResourceReference|null, 1: array<string, mixed>}
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
     * @param  false|\SineMacula\Laravel\Authorization\Support\ResourceReference|null  $resource
     * @param  array<string, mixed>  $context
     * @return array{0: false|\SineMacula\Laravel\Authorization\Support\ResourceReference|null, 1: array<string, mixed>}
     */
    private static function applyPositionalGateArgument(int $key, mixed $value, false|ResourceReference|null $resource, array $context): array
    {
        $isContextMap = \is_array($value) && !\array_is_list($value);

        if ($key === 0 && !$isContextMap) {
            return [ResourceReferences::of($value), $context];
        }

        if (!$isContextMap) {
            return [$resource, $context];
        }

        /** @var array<string, mixed> $value */
        return [$resource, \array_merge($context, $value)];
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
