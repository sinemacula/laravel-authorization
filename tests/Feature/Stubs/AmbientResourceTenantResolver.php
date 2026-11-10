<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Contracts\ResourceTenantResolver;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * A resource tenant resolver for tests that places every model and every
 * `(type, id)` pair in the tenant in place when it is asked, as a resolver
 * reading the ambient scope would, and remembers the tenant each answer gave.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class AmbientResourceTenantResolver implements ResourceTenantResolver
{
    /** @var list<string|null> The id of the tenant each answer gave, in order, null for none. */
    public array $answered = [];

    /**
     * Return the tenant in place, recording it.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $resource
     * @return \SineMacula\Laravel\Authorization\Support\Reference|null
     */
    #[\Override]
    public function tenantOf(Model $resource): ?Reference
    {
        return $this->current();
    }

    /**
     * Return the tenant in place, recording it.
     *
     * @param  string  $type
     * @param  string  $id
     * @return \SineMacula\Laravel\Authorization\Support\Reference|null
     */
    #[\Override]
    public function tenantOfRecord(string $type, string $id): ?Reference
    {
        return $this->current();
    }

    /**
     * Return the tenant in place, or null for none, recording its id.
     *
     * @return \SineMacula\Laravel\Authorization\Support\Reference|null
     */
    private function current(): ?Reference
    {
        $pair = TenantScope::currentTenant();

        $this->answered[] = $pair[1] ?? null;

        return $pair === null ? null : new Reference(...$pair);
    }
}
