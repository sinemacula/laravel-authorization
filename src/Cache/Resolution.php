<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Cache;

use SineMacula\Laravel\Authorization\Usage\RouteMap;

/**
 * What a resolution found: the value, how long it holds, whether it may be
 * stored, while grant usage is tracked, the routes of the stored grants behind
 * each permission or policy it found (see `Usage\RouteMap`), and the keys of
 * the break-glass activations behind each one a role read through one gave.
 *
 * @template-covariant TValue
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Resolution
{
    /**
     * Create a new resolution.
     *
     * @param  list<TValue>  $value
     * @param  int|null  $expiresIn
     * @param  bool  $stable
     * @param  \SineMacula\Laravel\Authorization\Usage\RouteMap|null  $routes
     * @param  array<string, list<string>>  $activations
     */
    public function __construct(

        /** The roles, permissions or policies found. */
        public array $value,

        /** Seconds until the nearest grant the value counts expires; null when none expires. */
        public ?int $expiresIn = null,

        /** Whether the records read stayed the same while the resolution ran, so the value may be stored. */
        public bool $stable = true,

        /** The routes behind each permission by its name, or each policy by its key, while usage is tracked; null when not tracked, or when the resolution cannot say. */
        public ?RouteMap $routes = null,

        /** The keys of the break-glass activations behind each permission by its name, or each policy by its key; none when no role was read through one. */
        public array $activations = [],
    ) {}
}
