<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Contracts;

/**
 * Bulk resource tenant resolver contract (AUTHZ-4.4, AUTHZ-10.3).
 *
 * An optional addition to `ResourceTenantResolver` for a resolver that can
 * answer many records at once, which bulk checks (`checkMany()`, `canEach()`
 * and `filterAuthorized()`) ask before they decide each check, so a check over
 * many resources never reads one tenant per resource. A resolver that does not
 * implement it is asked about each resource on its own, which keeps every
 * decision exactly as it is, but costs a read per resource when it reads the
 * database.
 *
 * Each answer is the one the per-item method would give: null for no tenant,
 * and, for a record, false when the resolver cannot tell (the record cannot be
 * found, say). A key left out of the answer is asked on its own through the
 * per-item method, so a resolver can leave out whatever it cannot answer in
 * bulk, a record whose tenant cannot be read included, and that record's check
 * alone fails as it would on its own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface BulkResourceTenantResolver extends ResourceTenantResolver
{
    /**
     * Return the tenant that owns each model, keyed as the models are, null for
     * one that has none or whose tenant the resolver does not know.
     *
     * @param  array<array-key, \Illuminate\Database\Eloquent\Model>  $models
     * @return array<array-key, \SineMacula\Laravel\Authorization\Support\Reference|null>
     *
     * @throws \Throwable
     */
    public function tenantsOf(array $models): array;

    /**
     * Return the tenant that owns each record of the type, keyed as the ids
     * are: null for one that has none, or false when the resolver cannot tell.
     *
     * @param  string  $type
     * @param  array<array-key, string>  $ids
     * @return array<array-key, false|\SineMacula\Laravel\Authorization\Support\Reference|null>
     *
     * @throws \Throwable
     */
    public function tenantsOfRecords(string $type, array $ids): array;
}
