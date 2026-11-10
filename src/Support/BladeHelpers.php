<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Diagnostics\PackageState;
use SineMacula\Laravel\Authorization\Subject;

/**
 * Runtime helpers that the shipped Blade directives compile into.
 *
 * The directives register thin callbacks that delegate here. The permission
 * directives decide each action through the authorization manager's full
 * decision for the subject, as `Authorization::can()`, `@can` and the Gate do:
 * policies, an explicit deny, the permissions held and the subject's tenant.
 * The role directives check role membership on the subject the bound
 * `SubjectResolver` resolves, through its `hasRole()`; a role is not an action,
 * so policies do not apply to it. A request with no subject, or a subject that
 * cannot hold roles, evaluates as `false`, keeping the view layer fail-closed.
 *
 * Every helper takes the names as a string or a list, each entry holding one or
 * more names separated by `|`, and an optional guard. The role helpers honour
 * the guard; the permission helpers refuse it, since no guard changes the
 * decision.
 *
 * Each helper, and so each directive, refuses while the package is not healthy
 * (see `PackageState`), before the manager is resolved.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class BladeHelpers
{
    /**
     * Return the current subject, or null when the manager cannot be
     * constructed (tests that run without the service provider booted) or the
     * resolver reports no subject. The helpers check the model it is about.
     *
     * Delegates to `AuthorizationManager::currentSubject()` so the Blade
     * surface resolves the same subject as the facade, Gate, and middleware
     * paths.
     *
     * @return \SineMacula\Laravel\Authorization\Subject|null
     */
    public static function currentSubject(): ?Subject
    {
        PackageState::guardCurrent();

        return AuthorizationManager::instance()?->currentSubject();
    }

    /**
     * Whether the current subject holds at least one of the supplied roles.
     *
     * @param  array<int, string>|string  $roles
     * @param  string|null  $guard
     * @return bool
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidCheckArgumentException
     */
    public static function hasRole(array|string $roles, ?string $guard = null): bool
    {
        PackageState::guardCurrent();

        $guard   = CheckArguments::guard($guard);
        $subject = self::currentSubject();

        if ($subject === null) {
            return false;
        }

        foreach (CheckArguments::names($roles) as $role) {
            if (SubjectGrants::holdsRole($subject, $role, $guard)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether the current subject holds every supplied role.
     *
     * @param  array<int, string>|string  $roles
     * @param  string|null  $guard
     * @return bool
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidCheckArgumentException
     */
    public static function hasAllRoles(array|string $roles, ?string $guard = null): bool
    {
        PackageState::guardCurrent();

        $guard    = CheckArguments::guard($guard);
        $subject  = self::currentSubject();
        $required = CheckArguments::names($roles);

        if ($subject === null || $required === []) {
            return false;
        }

        foreach ($required as $role) {
            if (!SubjectGrants::holdsRole($subject, $role, $guard)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Whether the full decision allows the current subject at least one of the
     * supplied actions.
     *
     * @param  array<int, string>|string  $permissions
     * @param  string|null  $guard
     * @return bool
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidCheckArgumentException
     */
    public static function hasPermission(array|string $permissions, ?string $guard = null): bool
    {
        PackageState::guardCurrent();

        CheckArguments::refuseGuard('permission', $guard);

        $manager = AuthorizationManager::instance();

        foreach (CheckArguments::names($permissions) as $permission) {
            if ($manager?->can($permission) === true) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether the full decision allows the current subject every supplied
     * action.
     *
     * @param  array<int, string>|string  $permissions
     * @param  string|null  $guard
     * @return bool
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidCheckArgumentException
     */
    public static function hasAllPermissions(array|string $permissions, ?string $guard = null): bool
    {
        PackageState::guardCurrent();

        CheckArguments::refuseGuard('permission', $guard);

        $manager  = AuthorizationManager::instance();
        $required = CheckArguments::names($permissions);

        if ($manager === null || $required === []) {
            return false;
        }

        foreach ($required as $permission) {
            if (!$manager->can($permission)) {
                return false;
            }
        }

        return true;
    }
}
