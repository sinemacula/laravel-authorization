<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exclusions;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * A pair of roles declared mutually exclusive (AUTHZ-11.8, N135), as stored:
 * the two roles, by reference, in the pair's canonical order, the lower key
 * first, so the pair reads the same whichever order it was declared in; the
 * tenant that owns it, or the platform; who declared it and when.
 *
 * A snapshot of plain values, never a model, as the role exclusion service
 * lists it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RoleExclusion
{
    /**
     * Create a new pair of mutually exclusive roles.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $role
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $excludedRole
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $grantedBy
     * @param  \Carbon\CarbonImmutable|null  $createdAt
     */
    public function __construct(

        /** The role of the pair with the lower key. */
        public Reference $role,

        /** The role of the pair with the higher key, which no holder of the first may hold where their reach overlaps. */
        public Reference $excludedRole,

        /** The tenant that owns the pair; null for the platform. */
        public ?Reference $tenant = null,

        /** Who declared the pair; null for trusted system work naming no one. */
        public ?Reference $grantedBy = null,

        /** When the pair was declared, in UTC; null when the row holds no time. */
        public ?CarbonImmutable $createdAt = null,
    ) {}
}
