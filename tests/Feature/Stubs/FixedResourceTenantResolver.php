<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Contracts\ResourceTenantResolver;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * A resource tenant resolver for tests that answers the same tenant, or none,
 * for every model and for every `(type, id)` pair, and remembers what it was
 * asked about.
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

    /** @var list<array{0: string, 1: string}> The pairs asked about, in order. */
    public array $askedRecords = [];

    /**
     * Create a new fixed resource tenant resolver.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  false|\SineMacula\Laravel\Authorization\Support\Reference|null  $recordTenant
     */
    public function __construct(

        /** The tenant every model belongs to; null for none. */
        private readonly ?Reference $tenant = null,

        /** The tenant every pair's record belongs to: null for none, false when it cannot tell. */
        private readonly false|Reference|null $recordTenant = null,
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

    /**
     * Return the fixed record tenant, recording the pair asked about.
     *
     * @param  string  $type
     * @param  string  $id
     * @return false|\SineMacula\Laravel\Authorization\Support\Reference|null
     */
    #[\Override]
    public function tenantOfRecord(string $type, string $id): false|Reference|null
    {
        $this->askedRecords[] = [$type, $id];

        return $this->recordTenant;
    }
}
