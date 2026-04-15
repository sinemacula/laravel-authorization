<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Contracts\SupportsPermissions;
use SineMacula\Laravel\Authorization\Contracts\SupportsRoles;

/**
 * Runtime helpers that the shipped Blade directives compile into.
 *
 * The directives register thin callbacks that delegate here; every
 * check resolves the current principal through the wired
 * `PrincipalResolver` so the view layer stays consistent with
 * Gate / facade evaluation in the same request. Anonymous
 * principals — or principals that do not implement the matching
 * narrow contract — evaluate as `false`, keeping the view layer
 * fail-closed by default.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class BladeHelpers
{
    /**
     * Return the currently resolved principal, or null when the
     * manager cannot be constructed (tests that run without the
     * service provider booted) or the resolver reports anonymous.
     *
     * Delegates to `AuthorizationManager::currentPrincipal()` so
     * the Blade surface resolves the same principal as the
     * facade, Gate, and middleware paths — see issue #85.
     *
     * @return object|null
     */
    public static function currentPrincipal(): ?object
    {
        if (!\function_exists('app') || !app()->bound(AuthorizationManager::class)) {
            return null;
        }

        return app(AuthorizationManager::class)->currentPrincipal();
    }

    /**
     * Whether the current principal holds at least one of the
     * supplied roles. Accepts either a single role name or an
     * array — the Blade directive passes the user-supplied
     * expression straight through.
     *
     * @param  array<int, string>|string  $roles
     * @return bool
     */
    public static function hasRole(array|string $roles): bool
    {
        $principal = self::currentPrincipal();

        if (!$principal instanceof SupportsRoles) {
            return false;
        }

        foreach (self::flatten($roles) as $role) {
            if ($principal->hasRole($role)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether the current principal holds every supplied role.
     *
     * @param  array<int, string>|string  $roles
     * @return bool
     */
    public static function hasAllRoles(array|string $roles): bool
    {
        $principal = self::currentPrincipal();

        if (!$principal instanceof SupportsRoles) {
            return false;
        }

        $required = self::flatten($roles);

        foreach ($required as $role) {
            if (!$principal->hasRole($role)) {
                return false;
            }
        }

        return $required !== [];
    }

    /**
     * Whether the current principal holds at least one of the
     * supplied permissions.
     *
     * @param  array<int, string>|string  $permissions
     * @return bool
     */
    public static function hasPermission(array|string $permissions): bool
    {
        $principal = self::currentPrincipal();

        if (!$principal instanceof SupportsPermissions) {
            return false;
        }

        foreach (self::flatten($permissions) as $permission) {
            if ($principal->hasPermission($permission)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether the current principal holds every supplied permission.
     *
     * @param  array<int, string>|string  $permissions
     * @return bool
     */
    public static function hasAllPermissions(array|string $permissions): bool
    {
        $principal = self::currentPrincipal();

        if (!$principal instanceof SupportsPermissions) {
            return false;
        }

        $required = self::flatten($permissions);

        foreach ($required as $permission) {
            if (!$principal->hasPermission($permission)) {
                return false;
            }
        }

        return $required !== [];
    }

    /**
     * Normalise a string-or-array argument into a flat list of
     * non-empty strings. Empty inputs are dropped so an accidental
     * `@role('')` never admits everyone.
     *
     * @param  array<int, string>|string  $value
     * @return array<int, string>
     */
    private static function flatten(array|string $value): array
    {
        $items = \is_array($value) ? $value : [$value];

        $result = [];

        foreach ($items as $item) {
            $trimmed = \trim($item);

            if ($trimmed !== '') {
                $result[] = $trimmed;
            }
        }

        return $result;
    }
}
