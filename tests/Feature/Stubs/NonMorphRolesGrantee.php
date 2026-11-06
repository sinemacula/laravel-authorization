<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use SineMacula\Laravel\Authorization\Concerns\HasPolicies;
use SineMacula\Laravel\Authorization\Contracts\SupportsPolicies;
use SineMacula\Laravel\Authorization\Contracts\SupportsRoles;
use SineMacula\Laravel\Authorization\Models\Role;

/**
 * A grantee that holds policies and declares that it supports roles, but whose
 * `roles()` relation is not a morph onto the role grants, so no role's policy
 * is read through it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class NonMorphRolesGrantee extends Model implements SupportsPolicies, SupportsRoles
{
    use HasPolicies;

    /** @var bool Disable auto-incrementing — stubs use explicit IDs. */
    public $incrementing = false;

    /** @var string Primary key type. */
    protected $keyType = 'string';

    /** @var list<string> Mass-assignable attributes. */
    protected $fillable = ['id', 'name'];

    /** @var string|null Backing table. */
    protected $table = 'stub_identities';

    /**
     * Belongs-to-many relation onto roles, not the morph the role grants use.
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsToMany<\SineMacula\Laravel\Authorization\Models\Role, $this>
     */
    public function roles(): BelongsToMany
    {
        return $this->belongsToMany(Role::class, 'authorizable_roles', 'authorizable_id', 'role_id');
    }

    /**
     * Assign a role (no-op stub).
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @return static
     */
    #[\Override]
    public function assignRole(Role|string $role): static
    {
        return $this;
    }

    /**
     * Revoke a role (no-op stub).
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @return static
     */
    #[\Override]
    public function revokeRole(Role|string $role): static
    {
        return $this;
    }

    /**
     * Sync roles (no-op stub).
     *
     * @param  array<int, \SineMacula\Laravel\Authorization\Models\Role|string>  $roles
     * @return static
     */
    #[\Override]
    public function syncRoles(array $roles): static
    {
        return $this;
    }

    /**
     * Report that the grantee has no role.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @param  string|null  $guard
     * @return bool
     */
    #[\Override]
    public function hasRole(Role|string $role, ?string $guard = null): bool
    {
        return false;
    }

    /**
     * List no roles.
     *
     * @return array<int, string>
     */
    #[\Override]
    public function getRoles(): array
    {
        return [];
    }
}
