<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Contracts;

use SineMacula\Laravel\Authorization\Support\IdentityPrincipals;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Identity directory contract (AUTHZ-14.2, N81).
 *
 * Principals and their identities live in the application (AUTHZ-13.9), so the
 * package learns which principals an identity owns only through this seam. The
 * grant scope query counts the grants of the identity and of every principal
 * the directory lists, and answers `unknown` unless the directory says its list
 * is complete: a principal left out could hold a grant outside the tenant, so
 * an incomplete list is never read as a complete one.
 *
 * The package never infers the principals of an identity, from
 * `AuthorizableIdentity` or from anything else: that contract says a model may
 * hold grants, not which principals an identity owns. The shipped default,
 * `GuardUserIdentityDirectory`, knows the answer only under the shipped subject
 * resolver, where every user is its own identity and owns no other principal;
 * under any other resolver it reports an incomplete list. An application with
 * principals, or the `sinemacula/laravel-iam` umbrella, binds its own
 * implementation, through `authorization.identity_directory` or on the
 * contract.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface IdentityDirectory
{
    /**
     * Return the principals the identity owns, the identity itself left out,
     * and whether that list is complete.
     *
     * A list is complete only when no principal of the identity is missing from
     * it. A directory that cannot tell, for an identity it does not know or a
     * store it cannot read, returns an incomplete list, with whatever
     * principals it does know.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $identity
     * @return \SineMacula\Laravel\Authorization\Support\IdentityPrincipals
     */
    public function principalsOf(Reference $identity): IdentityPrincipals;
}
