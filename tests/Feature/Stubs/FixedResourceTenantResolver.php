<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Contracts\ResourceTenantResolver;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * A resource tenant resolver for tests that answers the same tenant, or none,
 * for every model, and remembers the models it was asked about.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class FixedResourceTenantResolver implements ResourceTenantResolver
{
    /** @var list<\Illuminate\Database\Eloquent\Model> The models asked about, in order. */
    public array $asked = [];

    /**
     * Create a new fixed resource tenant resolver.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     */
    public function __construct(

        /** The tenant every model belongs to; null for none. */
        private readonly ?Reference $tenant = null,
    ) {}

    /**
     * Return the fixed tenant, recording the model asked about.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $resource
     * @return \SineMacula\Laravel\Authorization\Support\Reference|null
     */
    #[\Override]
    public function tenantOf(Model $resource): ?Reference
    {
        $this->asked[] = $resource;

        return $this->tenant;
    }
}
