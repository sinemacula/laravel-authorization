<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Contracts;

/**
 * Authorizable grantee contract.
 *
 * Composite contract implemented by models that hold roles, permissions and
 * policies: principals and identities alike. Split into three narrow sibling
 * contracts so consumers who only need a subset can typehint on the minimum
 * surface they actually implement:
 *
 * - `SupportsRoles` for role assignment / lookup.
 * - `SupportsPermissions` for direct-grant + role-inherited permission
 *   resolution.
 * - `SupportsPolicies` for policy attachment.
 *
 * The `Grantee` suffix avoids a name collision with Laravel's built-in
 * `Illuminate\Contracts\Auth\Access\Authorizable` contract.
 *
 * A grantee also says whether it is active: one that is not, as the subject of
 * a check or as the subject's identity, is denied everything.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface AuthorizableGrantee extends SupportsPermissions, SupportsPolicies, SupportsRoles
{
    /**
     * Determine whether the grantee is active.
     *
     * The `HasAuthorization` trait answers true; a model overrides it to report
     * a suspended or disabled grantee.
     *
     * @return bool
     */
    public function isAuthorizationActive(): bool;
}
