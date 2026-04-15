<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Models;

use Illuminate\Database\Eloquent\Relations\MorphPivot;

/**
 * Shared morph pivot for the temporal-grant tables.
 *
 * Used by `HasRoles::roles()`, `HasPermissions::permissions()`,
 * and `HasPolicies::policies()` so the `expires_at` column is
 * cast to Carbon when read through the relation. Consumers
 * inspecting `$role->pivot->expires_at` receive a
 * `Carbon|null` (matching the relation docblocks) rather than
 * the raw database string the default `MorphPivot` would
 * return.
 *
 * @property \Illuminate\Support\Carbon|null $expires_at
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
class AuthorizableGrantPivot extends MorphPivot
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
