<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Contracts;

/**
 * Contract for non-Eloquent tenant objects participating in tenant
 * scoping.
 *
 * The `TenantScope` global scope and the `scopeForTenant` local
 * scope on `Role` / `Permission` need two stable values to build a
 * morph-pair predicate: a persistent identifier and a type string.
 * Eloquent models supply both naturally via `getKey()` and
 * `getMorphClass()`. Any other object participating in tenant
 * scoping must implement this contract so the scope has an explicit
 * source of truth — there is no `spl_object_hash` fallback, which
 * produces request-scoped hashes that do not match previously-
 * persisted rows.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface TenantIdentifier
{
    /**
     * Return the stable, persisted identifier for this tenant.
     *
     * The returned value is written into the `tenant_id` column on
     * tenant-owned rows and used verbatim in scope predicates; it
     * must be stable across requests for the lifetime of the
     * tenant entity.
     *
     * @return string
     */
    public function getTenantIdentifier(): string;

    /**
     * Return the stable type discriminator for this tenant.
     *
     * The returned value is written into the `tenant_type` column
     * and used verbatim in scope predicates; it is the morph-type
     * analogue of `Model::getMorphClass()`.
     *
     * @return string
     */
    public function getTenantType(): string;
}
