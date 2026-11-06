<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Contracts;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Resource tenant resolver contract (AUTHZ-4.4).
 *
 * Answers which tenant owns the record a check is about, whether it is named by
 * its model or by a `(type, id)` pair, so a decision about a tenant-owned
 * object is made in the object's tenant and one outside the subject's scope is
 * refused as `tenant_scope` (AUTHZ-5.5), however the caller names it (N17). The
 * shipped default knows no tenant for any record (N10); an application binds
 * its own, reading a tenant column or looking the record up.
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

    /**
     * Return the tenant that owns the record a `(type, id)` pair names, null
     * when it has none, or false when the resolver cannot tell (the record
     * cannot be found, say), which denies the check as `resource_unresolved`
     * rather than deciding it as a record of no tenant.
     *
     * @param  string  $type
     * @param  string  $id
     * @return false|\SineMacula\Laravel\Authorization\Support\Reference|null
     */
    public function tenantOfRecord(string $type, string $id): false|Reference|null;
}
