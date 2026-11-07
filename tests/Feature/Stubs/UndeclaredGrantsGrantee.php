<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphToMany;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;

/**
 * A grantee model with relations onto the package's permission, role and policy
 * grants that declares none of the contracts they belong to, so nothing that
 * asks for a contract reads its grants.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class UndeclaredGrantsGrantee extends Model // @phpstan-ignore sineMaculaLaravel.modelBehaviour
{
    /** @var bool Disable auto-incrementing — stubs use explicit IDs. */
    public $incrementing = false;

    /** @var string Primary key type. */
    protected $keyType = 'string';

    /** @var list<string> Mass-assignable attributes. */
    protected $fillable = ['id', 'name'];

    /** @var string|null Backing table. */
    protected $table = 'stub_identities';

    /**
     * Morph-to-many relation onto the permissions granted to this grantee.
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphToMany<\SineMacula\Laravel\Authorization\Models\Permission, $this>
     */
    public function permissions(): MorphToMany
    {
        return $this->morphToMany(Permission::class, 'authorizable', 'authorizable_permissions', 'authorizable_id', 'permission_id')->withPivot('expires_at');
    }

    /**
     * Morph-to-many relation onto the roles granted to this grantee.
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphToMany<\SineMacula\Laravel\Authorization\Models\Role, $this>
     */
    public function roles(): MorphToMany
    {
        return $this->morphToMany(Role::class, 'authorizable', 'authorizable_roles', 'authorizable_id', 'role_id')->withPivot('expires_at');
    }

    /**
     * Morph-to-many relation onto the policies attached to this grantee.
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphToMany<\SineMacula\Laravel\Authorization\Models\Policy, $this>
     */
    public function policies(): MorphToMany
    {
        return $this->morphToMany(Policy::class, 'authorizable', 'authorizable_policies', 'authorizable_id', 'policy_id')->withPivot('expires_at');
    }
}
