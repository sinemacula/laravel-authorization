<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Services;

use Illuminate\Container\Container;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;

/**
 * Answers whether a principal may use an application (AUTHZ-5.6, AUTHZ-13.4,
 * D23), for `laravel-authentication`'s application access contract.
 *
 * An application named in `authorization.application_access` requires the
 * permission it maps to: the full decision is asked whether the principal holds
 * it, on that application, so a grant made for that application counts and one
 * made for another does not. An application the configuration does not name is
 * open to every principal, as `laravel-authentication`'s default admits.
 *
 * Admission is decided without session caps, for people and machines alike
 * (N105): a principal being admitted holds no session yet, so the request's
 * credential scopes, which belong to whoever made the request, never cap it,
 * and a machine is not refused for lacking scopes it has yet to be given. The
 * denies, guardrails and boundaries still decide, through the one decision path
 * (D22). Once the session exists, its caps apply to every check.
 *
 * It only builds the check and asks the decision; it decides nothing itself.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class ApplicationAccess
{
    /**
     * Determine whether the principal may use the application, in the given
     * tenant: the principal's own, or null for a platform principal.
     *
     * The principal becomes the subject as the bound subject resolver's
     * `forUser()` makes it, and the check is decided on the application asked
     * about and in the tenant given, rather than the request's, since sign-in,
     * a switch and a refresh ask about a principal that is not yet, or no
     * longer, the request's. It is decided without session caps, so neither the
     * request's credential scopes nor a machine's missing ones refuse it.
     *
     * @param  string  $application
     * @param  object  $principal
     * @param  object|null  $tenant
     * @return bool
     */
    public function mayUse(string $application, object $principal, ?object $tenant): bool
    {
        $permission = self::permissionFor($application);

        if ($permission === null) {
            return true;
        }

        $manager = self::manager()->forUser($principal)->withoutSessionCaps();

        return TenantScope::within($tenant, $application, static fn (): bool => $manager->can($permission));
    }

    /**
     * Return the permission the application requires, or null when the
     * configuration names none for it.
     *
     * @param  string  $application
     * @return string|null
     */
    private static function permissionFor(string $application): ?string
    {
        /** @var array<string, string> $permissions */
        $permissions = config('authorization.application_access', []);

        return $permissions[$application] ?? null;
    }

    /**
     * Return the authorization manager the container builds.
     *
     * @return \SineMacula\Laravel\Authorization\AuthorizationManager
     */
    private static function manager(): AuthorizationManager
    {
        /** @var \SineMacula\Laravel\Authorization\AuthorizationManager */
        return Container::getInstance()->make(AuthorizationManager::class);
    }
}
