<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Contracts;

use SineMacula\Laravel\Authorization\Support\ResourceTenancy;

/**
 * Contract for an Eloquent model whose queries `whereAuthorized()` may scope
 * (AUTHZ-10.1): it declares where its records' tenant is, or that they have
 * none, so the scope and `check()` read the same tenant.
 *
 * The declaration is static, so it never depends on a record. The resource
 * tenant resolver the package binds answers the tenant of a declared model's
 * records from it, and the scope refuses a model that does not implement this
 * contract, as `model_undeclared`.
 *
 * By implementing it, a model promises that its key column and its tenant
 * columns are read raw: no accessor, cast or override changes them on load, and
 * no hook (a `retrieved` listener or observer, say) changes them once a record
 * is loaded, so the values the database compares are the values `check()` sees.
 * The scope refuses every breach it can detect: an override of `getKey`,
 * `getKeyName`, `getMorphClass`, `newFromBuilder`, `getAttribute`,
 * `getAttributes`, `getAttributeValue` or `setRawAttributes`, an accessor or a
 * cast on those columns (the key's own integer or string cast aside), and a
 * `retrieved` listener registered for the model.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface QueryableResource
{
    /**
     * Return where the model's records keep their tenant, or that they have
     * none.
     *
     * @return \SineMacula\Laravel\Authorization\Support\ResourceTenancy
     */
    public static function resourceTenancy(): ResourceTenancy;
}
