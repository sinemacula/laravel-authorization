<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use SineMacula\Laravel\Authorization\Models\Role;

/**
 * A role listed in a sync with a reach of its own: whether its grant in the
 * sync's tenant also holds in the tenants below it (AUTHZ-5.3).
 *
 * `GrantService::syncRoles()` and the `HasRoles` trait's `syncRoles()` take one
 * beside a role model or name, as `RoleReach::of($role, includeSubtree: true)`,
 * so one call can sync roles of both reaches. The sync then compares the role
 * and its reach: a role held live with the other reach is changed in place,
 * keeping its expiry; a model or name listed alone takes the call's reach only
 * where the sync grants or re-arms it, and a role held live keeps its reach. A
 * platform-wide grant counts everywhere, so a sync that writes platform-wide,
 * with no tenant named or owning every role, writes every role reaching below,
 * whatever its entry says. A role listed with both reaches is therefore refused
 * with `InvalidArgumentException` in a tenant, but goes ahead in a
 * platform-wide sync, where both entries name the same reach.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RoleReach
{
    /**
     * Create a new role reach.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @param  bool  $includeSubtree
     */
    private function __construct(

        /** The role, as a model or a name. */
        public Role|string $role,

        /** Whether the role's grant also holds in the tenants below the sync's tenant. */
        public bool $includeSubtree,
    ) {}

    /**
     * Return the role with the given reach.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @param  bool  $includeSubtree
     * @return self
     */
    public static function of(Role|string $role, bool $includeSubtree): self
    {
        return new self($role, $includeSubtree);
    }

    /**
     * Split a sync's entries into its targets, each role model or name in the
     * order listed, and the reach each entry listed with one names, keyed by
     * the target's position.
     *
     * @param  array<array-key, mixed>  $entries
     * @return array{list<mixed>, array<int, bool>}
     *
     * @internal
     */
    public static function split(array $entries): array
    {
        $targets = [];
        $reaches = [];

        foreach (\array_values($entries) as $index => $entry) {
            if ($entry instanceof self) {
                $reaches[$index] = $entry->includeSubtree;
                $entry           = $entry->role;
            }

            $targets[] = $entry;
        }

        return [$targets, $reaches];
    }
}
