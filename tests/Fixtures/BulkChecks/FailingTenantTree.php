<?php

declare(strict_types = 1);

namespace Tests\Fixtures\BulkChecks;

use Illuminate\Contracts\Database\Query\Builder;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * A tenant tree held in memory, each tenant under the parent given, that cannot
 * be read for the tenants it is told fail, for bulk check tests: asking for
 * their ancestors, or whether they are within another, throws. Each read is
 * counted.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class FailingTenantTree implements TenantTree
{
    /** @var string The message a failure carries. */
    public const string MESSAGE = 'tenant tree unavailable';

    /** @var int How many times the tree was asked, for ancestors or whether a tenant is within another. */
    public int $reads = 0;

    /**
     * Create the tree.
     *
     * @param  array<string, \SineMacula\Laravel\Authorization\Support\Reference>  $parents
     * @param  list<string>  $failing
     */
    public function __construct(

        /** Each tenant's parent, keyed by the tenant's key. */
        private readonly array $parents = [],

        /** The keys of the tenants the tree cannot be read for. */
        private readonly array $failing = [],
    ) {}

    /**
     * Return the tenant's ancestors, nearest first, or throw for a tenant that
     * fails.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return list<\SineMacula\Laravel\Authorization\Support\Reference>
     *
     * @throws \RuntimeException
     */
    #[\Override]
    public function ancestors(Reference $tenant): array
    {
        $this->reads++;

        if (\in_array($tenant->id, $this->failing, true)) {
            throw new \RuntimeException(self::MESSAGE);
        }

        $ancestors = [];

        while (($tenant = $this->parents[$tenant->id] ?? null) !== null) {
            $ancestors[] = $tenant;
        }

        return $ancestors;
    }

    /**
     * Determine whether the tenant is the ancestor or below it, or throw for a
     * tenant that fails.
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
        foreach ([$tenant, ...$this->ancestors($tenant)] as $node) {
            if ($node->type === $ancestor->type && $node->id === $ancestor->id) {
                return true;
            }
        }

        return false;
    }

    /**
     * Return the tenant alone, as a query.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return \Illuminate\Contracts\Database\Query\Builder
     */
    #[\Override]
    public function subtree(Reference $tenant): Builder
    {
        return DB::query()->selectRaw('? as tenant_type, ? as tenant_id', [$tenant->type, $tenant->id]);
    }
}
