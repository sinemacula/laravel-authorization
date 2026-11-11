<?php

declare(strict_types = 1);

namespace Tests\Fixtures\TenantTrees;

use Illuminate\Contracts\Database\Query\Builder;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Fixtures\QueryScoping\ClosureTenantTree;

/**
 * A broken tenant tree, as an adapter over a tree that keeps ids alone would be
 * if it guessed: it answers ancestors and `isWithin()` as the closure table
 * holds them, but its subtree finds the tenants below every tenant with the id
 * asked about, whatever its type, and types each with the type asked about.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RootTypedTenantTree implements TenantTree
{
    /**
     * Return the tenant's ancestors, as the closure table holds them.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return list<\SineMacula\Laravel\Authorization\Support\Reference>
     */
    #[\Override]
    public function ancestors(Reference $tenant): array
    {
        return (new ClosureTenantTree)->ancestors($tenant);
    }

    /**
     * Determine whether the tenant is the ancestor or below it, as the closure
     * table holds it.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $ancestor
     * @return bool
     */
    #[\Override]
    public function isWithin(Reference $tenant, Reference $ancestor): bool
    {
        return (new ClosureTenantTree)->isWithin($tenant, $ancestor);
    }

    /**
     * Return the tenants below any tenant with the id asked about, each typed
     * with the type asked about.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return \Illuminate\Contracts\Database\Query\Builder
     */
    #[\Override]
    public function subtree(Reference $tenant): Builder
    {
        return DB::table(ClosureTenantTree::TABLE)
            ->selectRaw('? as tenant_type', [$tenant->type])
            ->addSelect('descendant_id as tenant_id')
            ->where('ancestor_id', $tenant->id);
    }
}
