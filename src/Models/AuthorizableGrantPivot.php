<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Models;

use Illuminate\Database\Eloquent\Relations\MorphPivot;

/**
 * Shared base pivot for the three temporal-grant tables.
 *
 * Subclassed by `AuthorizableRolePivot`, `AuthorizablePermissionPivot`,
 * and `AuthorizablePolicyPivot` so `HasRoles::roles()`,
 * `HasPermissions::permissions()`, and `HasPolicies::policies()`
 * each bind a distinct pivot class via `->using(...)`. The per-table
 * split lets future per-table fields (tenant scoping, granted-by
 * audit, policy-attachment approval workflow) land on the specific
 * subclass without leaking the cast surface across the other two
 * tables (see issue #90).
 *
 * Consumers inspecting `$role->pivot->expires_at` receive a
 * `Carbon|null` (matching the relation docblocks) rather than the
 * raw database string the default `MorphPivot` would return.
 *
 * @property \Illuminate\Support\Carbon|null $expires_at
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
abstract class AuthorizableGrantPivot extends MorphPivot
{
    /**
     * Cast map for the pivot row.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'expires_at' => 'datetime',
    ];
}
