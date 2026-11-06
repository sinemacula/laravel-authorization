<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

/**
 * The keys of the policies an identity gets through its roles, the seconds
 * until the nearest of the grants they come through expires, and whether the
 * role hierarchy stayed the same while they were read.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class InheritedPolicies
{
    /**
     * Create a new set of inherited policies.
     *
     * @param  list<string>  $keys
     * @param  int|null  $expiresIn
     * @param  bool  $stable
     */
    public function __construct(

        /** The keys of the policies, each once. */
        public array $keys = [],

        /** The seconds until the nearest grant expires; null when none does. */
        public ?int $expiresIn = null,

        /** Whether the hierarchy stayed the same while it was read. */
        public bool $stable = true,
    ) {}
}
