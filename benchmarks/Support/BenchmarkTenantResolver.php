<?php

declare(strict_types = 1);

namespace Benchmarks\Support;

use SineMacula\Laravel\Authorization\Contracts\TenantResolver;

/**
 * Non-null tenant resolver used by the tenant-scope bench.
 *
 * Returns a stable `BenchmarkTenant` every call so the memoised
 * resolver result is identity-stable across the request and the
 * warm / cold benches measure only the scope apply path.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
final class BenchmarkTenantResolver implements TenantResolver
{
    /**
     * Return a fresh `BenchmarkTenant`.
     *
     * @return object|null
     *
     * @phpstan-ignore-next-line return.unusedType
     */
    #[\Override]
    public function resolve(): ?object
    {
        return new BenchmarkTenant;
    }
}
