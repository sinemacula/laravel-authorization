<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Contracts;

/**
 * Tenant resolver contract.
 *
 * Bridges the authorization engine to whatever concept of "the current
 * tenant" the host application uses. The default binding returns null
 * so the package is single-tenant-safe and carries no hard runtime
 * dependency on any tenancy layer. Host applications or ecosystem
 * umbrella packages bind their own implementation when they want role
 * and permission queries scoped to a tenant context.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface TenantResolver
{
    /**
     * Resolve the current tenant, or null when no tenant context
     * is active (platform-level / global scope).
     *
     * @return object|null
     */
    public function resolve(): ?object;
}
