<?php

declare(strict_types = 1);

namespace Tests\Fixtures\QueryScoping;

use Illuminate\Contracts\Database\Query\Builder;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * A tenant tree that answers as another does, counting how often it is asked
 * for a tenant's ancestors and whether a tenant is within another, so a test
 * can tell how much of the tree a scope walks.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CountingTenantTree implements TenantTree
{
    /** @var int How often a tenant's ancestors were asked for. */
    public int $ancestorsRead = 0;

    /** @var int How often whether a tenant is within another was asked. */
    public int $withinAsked = 0;

    /**
     * Create a new counting tree.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\TenantTree  $tree
     */
    public function __construct(

        /** The tree answered as. */
        private readonly TenantTree $tree,
    ) {}

    /**
     * Return the tenant's ancestors, as the tree answers, counting the ask.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return list<\SineMacula\Laravel\Authorization\Support\Reference>
     */
    #[\Override]
    public function ancestors(Reference $tenant): array
    {
        $this->ancestorsRead++;

        return $this->tree->ancestors($tenant);
    }

    /**
     * Determine whether the tenant is within the ancestor, as the tree answers,
     * counting the ask.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $ancestor
     * @return bool
     */
    #[\Override]
    public function isWithin(Reference $tenant, Reference $ancestor): bool
    {
        $this->withinAsked++;

        return $this->tree->isWithin($tenant, $ancestor);
    }

    /**
     * Return the tenant's subtree, as the tree answers.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return \Illuminate\Contracts\Database\Query\Builder
     */
    #[\Override]
    public function subtree(Reference $tenant): Builder
    {
        return $this->tree->subtree($tenant);
    }
}
