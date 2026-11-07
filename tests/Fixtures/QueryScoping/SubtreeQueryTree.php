<?php

declare(strict_types = 1);

namespace Tests\Fixtures\QueryScoping;

use Illuminate\Contracts\Database\Query\Builder;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * A tenant tree that answers as the closure-table tree does, but writes each
 * subtree with the query a test gives, so a test can nest an Eloquent query,
 * one on another connection, or one whose text cannot be inlined.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SubtreeQueryTree implements TenantTree
{
    /**
     * Create a new tree writing its subtrees with the query given.
     *
     * @param  \Closure(\SineMacula\Laravel\Authorization\Support\Reference): \Illuminate\Contracts\Database\Query\Builder  $subtree
     */
    public function __construct(

        /** Writes a tenant's subtree. */
        private \Closure $subtree,
    ) {}

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
     * Return the tenant's subtree, written by the query given.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return \Illuminate\Contracts\Database\Query\Builder
     */
    #[\Override]
    public function subtree(Reference $tenant): Builder
    {
        return ($this->subtree)($tenant);
    }
}
