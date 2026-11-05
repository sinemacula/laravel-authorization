<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Resolvers;

use SineMacula\Laravel\Authorization\Contracts\TenantResolver;

/**
 * Single-tenant-safe default tenant resolver.
 *
 * Always returns null, so only platform-wide role and permission rows are
 * visible; tenant-owned rows never show without their tenant. Applications wire
 * their own resolver — typically one backed by a tenancy package or request
 * middleware — through the `authorization.tenant_resolver` config entry or by
 * binding the resolver contract directly.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class NullTenantResolver implements TenantResolver
{
    /**
     * Always resolve to no tenant context.
     *
     * @return object|null
     */
    #[\Override]
    public function resolve(): ?object
    {
        return null;
    }
}
