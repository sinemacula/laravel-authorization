<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use SineMacula\Laravel\Authorization\Contracts\TenantResolver;

/**
 * Tenant resolver whose tenant a test sets per simulated request or job, the
 * way a real resolver reads the tenant from the request or the job's payload.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SwitchableTenantResolver implements TenantResolver
{
    /** @var object|null The tenant every resolver instance returns until changed. */
    public static ?object $tenant = null;

    /**
     * Resolve the tenant currently set on the class.
     *
     * @return object|null
     */
    #[\Override]
    public function resolve(): ?object
    {
        return self::$tenant;
    }
}
