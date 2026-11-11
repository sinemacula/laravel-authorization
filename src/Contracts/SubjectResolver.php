<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Contracts;

use SineMacula\Laravel\Authorization\Subject;

/**
 * Subject resolver contract.
 *
 * Bridges the authorization engine to whatever the host application knows about
 * the current request: who it is about (the subject and its identity), the
 * active tenant, the application and the guard. Every check that does not name
 * its subject takes it from here, and the tenant scope reads the active tenant
 * from here.
 *
 * A resolver that knows the credential the subject acts with fills the
 * subject's `scopes` from it, for the session policy source to cap its checks
 * with (N121, N126): `CredentialScopes::uncapped()` for a credential carrying
 * no cap, and `CredentialScopes::of()` with the scopes it carries, an empty
 * list for one carrying none granted. Leaving `scopes` null says nothing about
 * them, so the source establishes them from the subject's session or guard, and
 * fails closed when it cannot. A resolver may mark the request's subject acting
 * on the platform, a job's or a console command's acting for no tenant, with
 * `platform` (N120), which names no tenant. The marker does not move
 * `forUser()` or a model named through `for()`: both are decided in the scope
 * in place, which for a request whose subject names no tenant is already the
 * platform, and which an explicit `AuthorizationScope::within()` replaces. Only
 * a `Subject` a caller passes to `for()` carrying the marker is decided on the
 * platform whatever scope is in place.
 *
 * The shipped default reads Laravel's authenticated user on the default guard,
 * with no tenant and the guard's name as the application, and fills neither the
 * scopes nor the marker. An application with principals or tenants, or the
 * `sinemacula/laravel-iam` umbrella, binds its own implementation.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface SubjectResolver
{
    /**
     * Resolve the subject of the current request or job.
     *
     * Returns null when there is none (an anonymous request, or a job acting
     * for no one), and every check without a named subject then denies.
     *
     * @return \SineMacula\Laravel\Authorization\Subject|null
     */
    public function resolve(): ?Subject;

    /**
     * Translate the user Laravel's Gate hands over into the subject decisions
     * are about, in the current request's tenant, application and guard.
     *
     * In an application without principals the user is the subject. One with
     * principals returns the principal the user acts as.
     *
     * @param  object  $user
     * @return \SineMacula\Laravel\Authorization\Subject
     */
    public function forUser(object $user): Subject;
}
