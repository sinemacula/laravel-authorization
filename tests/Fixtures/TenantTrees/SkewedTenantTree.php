<?php

declare(strict_types = 1);

namespace Tests\Fixtures\TenantTrees;

use Illuminate\Contracts\Database\Query\Builder;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Fixtures\QueryScoping\ClosureTenantTree;

/**
 * A tenant tree that answers as the closure-table tree does, except for the
 * answers a test gives, so a test can break one answer at a time.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SkewedTenantTree implements TenantTree
{
    /** @var \Tests\Fixtures\QueryScoping\ClosureTenantTree The tree answering what the test leaves alone. */
    private ClosureTenantTree $closure;

    /**
     * Create a new tree answering as the closure table does, but for the
     * answers given.
     *
     * @param  (\Closure(\SineMacula\Laravel\Authorization\Support\Reference): list<\SineMacula\Laravel\Authorization\Support\Reference>)|null  $ancestors
     * @param  (\Closure(\SineMacula\Laravel\Authorization\Support\Reference, \SineMacula\Laravel\Authorization\Support\Reference): bool)|null  $isWithin
     * @param  (\Closure(\SineMacula\Laravel\Authorization\Support\Reference): \Illuminate\Contracts\Database\Query\Builder)|null  $subtree
     */
    public function __construct(

        /** Answers a tenant's ancestors, if given. */
        private ?\Closure $ancestors = null,

        /** Answers whether a tenant is within another, if given. */
        private ?\Closure $isWithin = null,

        /** Writes a tenant's subtree, if given. */
        private ?\Closure $subtree = null,
    ) {
        $this->closure = new ClosureTenantTree;
    }

    /**
     * Return the tenant's ancestors.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return list<\SineMacula\Laravel\Authorization\Support\Reference>
     */
    #[\Override]
    public function ancestors(Reference $tenant): array
    {
        return $this->ancestors === null ? $this->closure->ancestors($tenant) : ($this->ancestors)($tenant);
    }

    /**
     * Determine whether the tenant is the ancestor or below it.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $ancestor
     * @return bool
     */
    #[\Override]
    public function isWithin(Reference $tenant, Reference $ancestor): bool
    {
        return $this->isWithin === null ? $this->closure->isWithin($tenant, $ancestor) : ($this->isWithin)($tenant, $ancestor);
    }

    /**
     * Return the tenant's subtree.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return \Illuminate\Contracts\Database\Query\Builder
     */
    #[\Override]
    public function subtree(Reference $tenant): Builder
    {
        return $this->subtree === null ? $this->closure->subtree($tenant) : ($this->subtree)($tenant);
    }
}
