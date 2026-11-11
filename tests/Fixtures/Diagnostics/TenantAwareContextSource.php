<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Diagnostics;

use SineMacula\Laravel\Authorization\Contracts\ContextSource;
use SineMacula\Laravel\Authorization\Contracts\GrantUsageStore;
use SineMacula\Laravel\Authorization\Support\ResolvedTenant;

/**
 * A context source handed, as the container builds it, the tenant resolved for
 * the request and the grant usage store, which the boot's validation builds
 * while the package is pending.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class TenantAwareContextSource implements ContextSource
{
    /**
     * Create a new context source.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\ResolvedTenant  $tenant
     * @param  \SineMacula\Laravel\Authorization\Contracts\GrantUsageStore  $usage
     */
    public function __construct(

        /** The tenant resolved for the request or job. */
        public ResolvedTenant $tenant,

        /** The grant usage store. */
        public GrantUsageStore $usage,
    ) {}

    /**
     * Return the namespace the source supplies.
     *
     * @return string
     */
    #[\Override]
    public function namespace(): string
    {
        return 'tenancy';
    }

    /**
     * Return whether a tenant is resolved.
     *
     * @return array<string, mixed>
     */
    #[\Override]
    public function values(): array
    {
        return ['resolved' => $this->tenant->tenant !== null];
    }
}
