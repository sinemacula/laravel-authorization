<?php

declare(strict_types = 1);

namespace Benchmarks\Support;

use SineMacula\Laravel\Authorization\Contracts\AuthorizableTenant;

/**
 * Bench tenant fixture — implements `AuthorizableTenant` so the
 * `TenantScope` morph-pair extraction accepts it without refusing
 * the value. Kept as a named class so PHPBench can serialise it
 * across its template boundary.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
final class BenchTenant implements AuthorizableTenant
{
    /**
     * Stable tenant key used by benches.
     *
     * @return string
     */
    public function getKey(): string
    {
        return 'bench-tenant';
    }

    /**
     * Stable morph class used by benches.
     *
     * @return string
     */
    public function getMorphClass(): string
    {
        return 'bench_tenant';
    }
}
