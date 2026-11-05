<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Models\Pivots;

use Illuminate\Database\Eloquent\Relations\MorphPivot;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Database\UtcDateTime;

/**
 * Shared base pivot for the three temporal-grant tables.
 *
 * Subclassed by `AuthorizableRolePivot`, `AuthorizablePermissionPivot`, and
 * `AuthorizablePolicyPivot` so `HasRoles::roles()`,
 * `HasPermissions::permissions()`, and `HasPolicies::policies()` each bind a
 * distinct pivot class via `->using(...)`. The scope columns (the tenant pair,
 * `include_subtree`, `application`) and the granted-by pair are shared by all
 * three tables; the per-table split lets future per-table fields (a
 * policy-attachment approval workflow, for example) land on the specific
 * subclass without leaking the cast surface across the other two tables.
 *
 * Consumers inspecting `$role->pivot->expires_at` receive a UTC `Carbon|null`
 * (matching the relation docblocks) rather than the raw database string the
 * default `MorphPivot` would return. The expiry is stored in UTC whatever zone
 * it was given in, so it lapses at the instant it names.
 *
 * @property \Illuminate\Support\Carbon|null $expires_at
 * @property \Illuminate\Support\Carbon|null $created_at
 * @property \Illuminate\Support\Carbon|null $updated_at
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
abstract class AuthorizableGrantPivot extends MorphPivot
{
    /** @var array<string, string> Cast map for the pivot row. */
    protected $casts = [
        'expires_at' => UtcDateTime::class,
    ];

    /**
     * Return the connection the grant table lives on: the configured
     * `authorization.connection`, or the application's default when it is
     * unset.
     *
     * Laravel hands a pivot the connection of the model the relation starts
     * from, which for a grant is the grantee's, so the pivot never uses the
     * connection it carries: a grant row stays with the package's tables
     * whichever connection its grantee lives on. Naming the connection is
     * schema, so this is a framework hook rather than model behaviour.
     *
     * @return string
     *
     * @phpstan-ignore sineMaculaLaravel.modelBehaviour
     */
    #[\Override]
    public function getConnectionName(): string
    {
        return AuthorizationConnection::resolve();
    }
}
