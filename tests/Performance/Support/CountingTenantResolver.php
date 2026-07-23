<?php

declare(strict_types = 1);

namespace Tests\Performance\Support;

use SineMacula\Laravel\Authorization\Contracts\AuthorizableTenant;
use SineMacula\Laravel\Authorization\Contracts\TenantResolver;

/**
 * Counting tenant resolver used by the memo-contract assertion - exposes
 * `$calls` so the test can prove single-invocation semantics.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CountingTenantResolver implements TenantResolver
{
    /** @var int Number of times `resolve` was invoked. */
    public int $calls = 0;

    /**
     * Create a new counting resolver wrapping a fixed tenant.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\AuthorizableTenant  $tenant
     * @return void
     */
    public function __construct(

        /** The tenant returned by every resolution call. */
        private readonly AuthorizableTenant $tenant,
    ) {}

    /**
     * Resolve the tenant and increment the call counter.
     *
     * @return object|null
     *
     * @phpstan-ignore-next-line return.unusedType
     */
    #[\Override]
    public function resolve(): ?object
    {
        $this->calls++;

        return $this->tenant;
    }
}
