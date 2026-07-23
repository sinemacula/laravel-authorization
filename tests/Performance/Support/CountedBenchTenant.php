<?php

declare(strict_types = 1);

namespace Tests\Performance\Support;

use SineMacula\Laravel\Authorization\Contracts\AuthorizableTenant;

/**
 * Minimal tenant fixture - kept here rather than in a shared helper so the
 * performance suite has no runtime dependency on the benchmark-support tree.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CountedBenchTenant implements AuthorizableTenant
{
    /**
     * The fixed tenant key.
     *
     * @return string
     */
    #[\Override]
    public function getKey(): string
    {
        return 'bench-tenant';
    }

    /**
     * The fixed tenant morph class.
     *
     * @return string
     */
    #[\Override]
    public function getMorphClass(): string
    {
        return 'bench_tenant';
    }
}
