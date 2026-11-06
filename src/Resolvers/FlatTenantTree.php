<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Resolvers;

use Illuminate\Contracts\Database\Query\Builder;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * The default tenant tree: a flat set of tenants, none with a parent.
 *
 * A grant in a tenant applies only there, and a tenant sees only its own and
 * the platform's roles, permissions and policies.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class FlatTenantTree implements TenantTree
{
    /**
     * Return no ancestors: no tenant has a parent.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return list<\SineMacula\Laravel\Authorization\Support\Reference>
     */
    #[\Override]
    public function ancestors(Reference $tenant): array
    {
        return [];
    }

    /**
     * Determine whether the tenant is the other: nothing is below a tenant.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $ancestor
     * @return bool
     */
    #[\Override]
    public function isWithin(Reference $tenant, Reference $ancestor): bool
    {
        return $tenant->type === $ancestor->type && $tenant->id === $ancestor->id;
    }

    /**
     * Return the tenant alone as a one-row query.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return \Illuminate\Contracts\Database\Query\Builder
     */
    #[\Override]
    public function subtree(Reference $tenant): Builder
    {
        return AuthorizationConnection::connection()->query()->selectRaw('? as tenant_type, ? as tenant_id', [$tenant->type, $tenant->id]);
    }
}
