<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Contracts;

use Illuminate\Contracts\Database\Query\Builder;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Tenant tree contract (AUTHZ-5.3).
 *
 * The tenant tree is the application's: this package never stores it, and
 * learns it only through this seam. A grant in a tenant applies there and,
 * unless it is limited to its own tenant, in every tenant below it; a tenant
 * sees the roles, permissions and policies its ancestors own as well as its own
 * and the platform's.
 *
 * The shipped default is a flat set of tenants: no tenant has a parent, so a
 * grant applies only in its own tenant. An application with a hierarchy (an
 * organisation above its accounts, say) binds its own implementation, over a
 * recursive query, a closure table or a materialised path it owns, and reports
 * a change to the tree through `Authorization::treeChanged($tenant)`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface TenantTree
{
    /**
     * Return the tenant's ancestors, nearest first, the tenant itself left out:
     * none for a tenant at the top of the tree.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return list<\SineMacula\Laravel\Authorization\Support\Reference>
     */
    public function ancestors(Reference $tenant): array;

    /**
     * Determine whether the tenant is the ancestor itself or anywhere below it.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $ancestor
     * @return bool
     */
    public function isWithin(Reference $tenant, Reference $ancestor): bool;

    /**
     * Return the tenant and every tenant below it as a query selecting their
     * `tenant_type` and `tenant_id`, for a scope to join or nest, never a list
     * of keys loaded into PHP.
     *
     * `subtree(T)` selects exactly the string forms (`tenant_type`,
     * `tenant_id`) of every R with `isWithin(R, T)`, and does not depend on
     * `TenantScope`. Two readers nest it whole in a query of their own, so each
     * needs it on that query's connection. `whereAuthorized()` nests it to tell
     * the rows of a subtree, so there it must be a query on the connection of
     * the models it scopes, and one on any other is refused as
     * `subtree_connection`. The grant scope query
     * (`GrantScopeQuery::forIdentity()`) nests it in its query of the grant
     * tables, so there it must be a query on the package's connection
     * (`authorization.connection`), and one on any other is a tree that cannot
     * be read, answered `unknown` unless a platform-wide grant proves
     * `outside`. A tree kept on the connection of both the scoped models and
     * the package's tables serves both.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return \Illuminate\Contracts\Database\Query\Builder
     */
    public function subtree(Reference $tenant): Builder;
}
