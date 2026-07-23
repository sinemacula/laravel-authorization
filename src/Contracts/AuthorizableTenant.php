<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Contracts;

/**
 * Contract for non-Eloquent tenant objects participating in tenant scoping.
 *
 * Parallels `AuthorizableIdentity` — a noun-form contract that marks an object
 * as "a tenant that can own authorization rows." The two accessors mirror
 * Eloquent's `Model::getKey()` and `Model::getMorphClass()` verbatim so an
 * Eloquent Model satisfies the contract's shape by construction; non-Model
 * tenants implement the same pair explicitly.
 *
 * The `TenantScope` global scope and the `scopeForTenant` local scope on `Role`
 * / `Permission` need two stable values to build a morph-pair predicate: a
 * persistent identifier and a type string. Non-Model tenants without this
 * contract are refused at the scope boundary via `InvalidTenantException` —
 * there is no `spl_object_hash` fallback, which would produce request-scoped
 * hashes that do not match previously-persisted rows.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface AuthorizableTenant
{
    /**
     * Return the stable, persisted identifier for this tenant.
     *
     * Matches `Model::getKey()` so an Eloquent Model satisfies the shape
     * without additional glue. The returned value is written into the
     * `tenant_id` column on tenant-owned rows and used verbatim in scope
     * predicates; it must be stable across requests for the lifetime of the
     * tenant entity.
     *
     * @return int|string
     */
    public function getKey(): int|string;

    /**
     * Return the stable type discriminator for this tenant.
     *
     * Matches `Model::getMorphClass()` so an Eloquent Model satisfies the shape
     * without additional glue. The returned value is written into the
     * `tenant_type` column and used verbatim in scope predicates.
     *
     * @return string
     */
    public function getMorphClass(): string;
}
