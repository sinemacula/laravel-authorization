<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use Illuminate\Contracts\Database\Query\Builder;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * An in-memory tenant tree for tests: each tenant may be put under a parent,
 * and every read of a tenant's ancestors is counted.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class StubTenantTree implements TenantTree
{
    /** @var int How many times a tenant's ancestors were read. */
    public int $reads = 0;

    /** @var array<string, \SineMacula\Laravel\Authorization\Support\Reference> Each tenant's parent, keyed by the tenant's type and key. */
    private array $parents = [];

    /** @var array<string, \SineMacula\Laravel\Authorization\Support\Reference> Each tenant put in the tree, keyed by its type and key. */
    private array $tenants = [];

    /**
     * Put the tenant under the parent, or at the top of the tree for none.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $parent
     * @return self
     */
    public function put(Reference $tenant, ?Reference $parent): self
    {
        unset($this->parents[self::key($tenant)]);

        $this->tenants[self::key($tenant)] = $tenant;

        if ($parent !== null) {
            $this->parents[self::key($tenant)] = $parent;
        }

        return $this;
    }

    /**
     * Return the tenant's ancestors, nearest first.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return list<\SineMacula\Laravel\Authorization\Support\Reference>
     */
    #[\Override]
    public function ancestors(Reference $tenant): array
    {
        $this->reads++;

        $ancestors = [];

        while (($tenant = $this->parents[self::key($tenant)] ?? null) !== null) {
            $ancestors[] = $tenant;
        }

        return $ancestors;
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
        foreach ([$tenant, ...$this->ancestors($tenant)] as $node) {
            if (self::key($node) === self::key($ancestor)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Return the tenant and every tenant put below it, as a query on the
     * default connection; reading it counts no read of ancestors.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return \Illuminate\Contracts\Database\Query\Builder
     */
    #[\Override]
    public function subtree(Reference $tenant): Builder
    {
        $query = DB::query()->selectRaw('? as tenant_type, ? as tenant_id', [$tenant->type, $tenant->id]);

        foreach ($this->tenants as $key => $below) {
            if ($key === self::key($tenant) || !$this->isBelow($key, $tenant)) {
                continue;
            }

            $query->unionAll(DB::query()->selectRaw('? as tenant_type, ? as tenant_id', [$below->type, $below->id]));
        }

        return $query;
    }

    /**
     * Determine whether the tenant held under the key is below the ancestor,
     * walking its parents.
     *
     * @param  string  $key
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $ancestor
     * @return bool
     */
    private function isBelow(string $key, Reference $ancestor): bool
    {
        while (($parent = $this->parents[$key] ?? null) !== null) {
            if (self::key($parent) === self::key($ancestor)) {
                return true;
            }

            $key = self::key($parent);
        }

        return false;
    }

    /**
     * Return the key a tenant is held under.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $tenant
     * @return string
     */
    private static function key(Reference $tenant): string
    {
        return "{$tenant->type}:{$tenant->id}";
    }
}
