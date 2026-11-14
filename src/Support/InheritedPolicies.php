<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

/**
 * The keys of the policies an identity gets through its roles, the seconds
 * until the nearest of the grants they come through expires, whether the role
 * hierarchy stayed the same while they were read, and, read for grant usage
 * tracking, the chain of each role held and the policies attached to each role;
 * the keys of those reached only through an attachment whose denies alone
 * count, one naming half a tenant (see `TenantColumns`); and the keys of the
 * break-glass activations behind each policy a role read through one gives.
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
     * @param  array<string, list<string>>|null  $chains
     * @param  array<string, list<string>>  $byRole
     * @param  list<string>  $denyOnly
     * @param  array<string, list<string>>  $activations
     */
    public function __construct(

        /** The keys of the policies; one held through several roles repeats. */
        public array $keys = [],

        /** The seconds until the nearest grant expires; null when none does. */
        public ?int $expiresIn = null,

        /** Whether the hierarchy stayed the same while it was read. */
        public bool $stable = true,

        /** The chain of each role held, from the role up, by its key; null when not read, or when the hierarchy moved. */
        public ?array $chains = null,

        /** The keys of the policies attached to each role, by the role's key; empty when not read. */
        public array $byRole = [],

        /** The keys of the policies reached only through attachments whose denies alone count. */
        public array $denyOnly = [],

        /** The keys of the break-glass activations behind each policy, by its key; none when no role was read through one. */
        public array $activations = [],
    ) {}
}
