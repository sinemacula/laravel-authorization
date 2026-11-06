<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use Illuminate\Auth\Access\Response;
use SineMacula\Laravel\Authorization\Concerns\DecidesThroughAuthorization;

/**
 * A Laravel policy class that decides through the package, each method naming
 * its action, so a test can show what a policy method using the trait returns
 * through the Gate and when called directly.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class DecidingLaravelPolicy
{
    use DecidesThroughAuthorization;

    /**
     * Decide whether the user may publish the tenant.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity|null  $user
     * @param  \Tests\Feature\Stubs\StubTenant  $tenant
     * @return \Illuminate\Auth\Access\Response
     */
    public function publish(?StubIdentity $user, StubTenant $tenant): Response
    {
        return $this->decide($user, 'tenants:publish', $tenant);
    }

    /**
     * Decide the action for the user on the resource, as any policy method of
     * the trait would.
     *
     * @param  object|null  $user
     * @param  string  $action
     * @param  mixed  $resource
     * @param  array<string, mixed>  $context
     * @return \Illuminate\Auth\Access\Response
     */
    public function decideFor(?object $user, string $action, mixed $resource = null, array $context = []): Response
    {
        return $this->decide($user, $action, $resource, $context);
    }
}
