<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphToMany;
use SineMacula\Laravel\Authorization\Concerns\HasPolicies;
use SineMacula\Laravel\Authorization\Contracts\SupportsPolicies;
use SineMacula\Laravel\Authorization\Models\Role;

/**
 * A grantee that holds policies and has a `roles()` relation onto the role
 * grants, without declaring that it supports roles, so its roles' policies are
 * not its own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class UndeclaredRolesGrantee extends Model implements SupportsPolicies // @phpstan-ignore sineMaculaLaravel.modelBehaviour, sineMaculaLaravel.modelBehaviour
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
     * Morph-to-many relation onto the roles granted to this grantee.
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphToMany<\SineMacula\Laravel\Authorization\Models\Role, $this>
     */
    public function roles(): MorphToMany
    {
        return $this->morphToMany(Role::class, 'authorizable', 'authorizable_roles', 'authorizable_id', 'role_id')->withPivot('expires_at');
    }
}
