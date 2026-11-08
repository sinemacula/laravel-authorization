<?php

declare(strict_types = 1);

namespace Tests\Fixtures\GrantScope;

use Illuminate\Contracts\Database\Query\Builder;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * A tenant tree that cannot be read: every question about it throws, as a tree
 * whose store is down would.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class UnreadableTenantTree implements TenantTree
{
    /** @var string The message every question fails with. */
    public const string MESSAGE = 'The tenant tree is down.';

    /**
     * Fail to read the tenant's ancestors.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return list<\SineMacula\Laravel\Authorization\Support\Reference>
     *
     * @throws \RuntimeException
     */
    #[\Override]
    public function ancestors(Reference $tenant): array
    {
        throw new \RuntimeException(self::MESSAGE);
    }

    /**
     * Fail to tell whether one tenant is within another.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $ancestor
     * @return bool
     *
     * @throws \RuntimeException
     */
    #[\Override]
    public function isWithin(Reference $tenant, Reference $ancestor): bool
    {
        throw new \RuntimeException(self::MESSAGE);
    }

    /**
     * Fail to build the tenant's subtree.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return \Illuminate\Contracts\Database\Query\Builder
     *
     * @throws \RuntimeException
     */
    #[\Override]
    public function subtree(Reference $tenant): Builder
    {
        throw new \RuntimeException(self::MESSAGE);
    }
}
