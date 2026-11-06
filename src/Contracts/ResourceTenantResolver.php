<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Contracts;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Resource tenant resolver contract (AUTHZ-4.4).
 *
 * Answers which tenant owns a model a check is about, so a decision about a
 * tenant-owned object is made in the object's tenant and one outside the
 * subject's scope is refused as `tenant_scope` (AUTHZ-5.5). The shipped default
 * knows no tenant for any model (N10); an application binds its own, reading a
 * tenant column or whatever its models carry.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface ResourceTenantResolver
{
    /**
     * Return the tenant that owns the model, or null when it has none or the
     * resolver does not know it.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $resource
     * @return \SineMacula\Laravel\Authorization\Support\Reference|null
     */
    public function tenantOf(Model $resource): ?Reference;
}
