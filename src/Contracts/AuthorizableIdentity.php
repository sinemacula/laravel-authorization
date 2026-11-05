<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Contracts;

/**
 * Authorizable identity contract.
 *
 * Composite contract implemented by identity models that participate in the
 * full authorization surface — roles, permissions, and policies. Split into
 * three narrow sibling contracts so consumers who only need a subset can
 * typehint on the minimum surface they actually implement:
 *
 * - `SupportsRoles` for role assignment / lookup.
 * - `SupportsPermissions` for direct-grant + role-inherited permission
 *   resolution.
 * - `SupportsPolicies` for per-identity policy attachment.
 *
 * The explicit `Identity` suffix avoids a name collision with Laravel's
 * built-in `Illuminate\Contracts\Auth\Access\Authorizable` contract.
 *
 * A grantee also says whether it is active: one that is not, as the subject of
 * a check or as the subject's identity, is denied everything.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface AuthorizableIdentity extends SupportsPermissions, SupportsPolicies, SupportsRoles
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
