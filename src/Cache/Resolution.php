<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Cache;

/**
 * What a resolution found: the value, how long it holds, and whether it may be
 * stored.
 *
 * @template TValue
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
     */
    public function __construct(

        /** The roles, permissions or policies found. */
        public array $value,

        /** Seconds until the nearest grant the value counts expires; null when none expires. */
        public ?int $expiresIn = null,

        /** Whether the records read stayed the same while the resolution ran, so the value may be stored. */
        public bool $stable = true,
    ) {}
}
