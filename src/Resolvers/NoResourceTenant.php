<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Resolvers;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Contracts\ResourceTenantResolver;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * The default resource tenant resolver: no model has a tenant, so no check is
 * refused for its resource's tenant until the application binds a resolver
 * (N10). A tenant a resource reference already carries is kept.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class NoResourceTenant implements ResourceTenantResolver
{
    /**
     * Return no tenant.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $resource
     * @return \SineMacula\Laravel\Authorization\Support\Reference|null
     */
    #[\Override]
    public function tenantOf(Model $resource): ?Reference
    {
        return null;
    }
}
