<?php

declare(strict_types = 1);

namespace Benchmarks\Support;

use SineMacula\Laravel\Authorization\Contracts\PrincipalResolver;

/**
 * Static-slot principal resolver for benches.
 *
 * Benches need to swap the resolved principal between revolutions
 * without rebuilding the container. The resolver is stateful on a
 * single slot so any bench can bind it once, flip the principal
 * per subject, and avoid a rebinding round-trip.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class BenchPrincipalResolver implements PrincipalResolver
{
    /**
     * Create a new resolver instance.
     *
     * @param  object|null  $principal
     */
    public function __construct(private ?object $principal = null) {}

    /**
     * Swap the resolved principal — used by benches that carve
     * admit / deny shapes on a shared resolver binding.
     *
     * @param  object|null  $principal
     * @return void
     */
    public function setPrincipal(?object $principal): void
    {
        $this->principal = $principal;
    }

    /**
     * Return the currently slotted principal.
     *
     * @return object|null
     */
    public function resolve(): ?object
    {
        return $this->principal;
    }
}
