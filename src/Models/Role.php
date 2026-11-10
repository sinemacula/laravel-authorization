<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Models;

use Illuminate\Database\Eloquent\Attributes\ObservedBy;
use Illuminate\Database\Eloquent\Attributes\ScopedBy;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use SineMacula\Laravel\Authorization\Concerns\HasPolicies;
use SineMacula\Laravel\Authorization\Concerns\HasRoleHierarchy;
use SineMacula\Laravel\Authorization\Concerns\HasSystemProtection;
use SineMacula\Laravel\Authorization\Concerns\ManagesPermissions;
use SineMacula\Laravel\Authorization\Concerns\ValidatesAuthorizationName;
use SineMacula\Laravel\Authorization\Config\TableNames;
use SineMacula\Laravel\Authorization\Contracts\SupportsPolicies;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Exceptions\SystemRoleProtectedException;
use SineMacula\Laravel\Authorization\Observers\RoleObserver;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;

/**
 * Eloquent model for role rows — named buckets of permissions shared across
 * authorizable identities. Behaviour is composed from `HasRoleHierarchy`,
 * `ManagesPermissions`, `HasPolicies`, `HasSystemProtection`, and the
 * `RoleObserver` wired via `#[ObservedBy]`.
 *
 * A role takes policies as an identity does, through the same
 * `authorizable_policies` table with the role as the grantee (AUTHZ-7.2). They
 * apply to whoever holds the role, where both the role's grant and the policy's
 * attachment hold, and are inherited down the hierarchy as the role's
 * permissions are. A role may own inline policies, deleted with it.
 *
 * @property string $id
 * @property string $name
 * @property string|null $guard
 * @property string|null $description
 * @property bool $is_system
 * @property string|null $parent_id
 * @property int|null $rank
 * @property string|null $tenant_type
 * @property string|null $tenant_id
 *
 * @inheritable
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
#[ObservedBy(RoleObserver::class)]
#[ScopedBy(TenantScope::class)]
class Role extends Model implements SupportsPolicies
{
    use HasPolicies, HasRoleHierarchy, HasSystemProtection, HasUuids, ManagesPermissions, ValidatesAuthorizationName;

    /** @var list<string> Attributes that are mass assignable. */
    protected $fillable = [
        'name',
        'guard',
        'description',
        'is_system',
        'parent_id',
        'rank',
        'tenant_type',
        'tenant_id',
    ];

    /**
     * Create a new Eloquent model instance.
     *
     * Binds the model to the table the package configuration names. The table
     * has to be set on each instantiation so runtime config swaps take effect,
     * so this is construction rather than model behaviour.
     *
     * @param  array<string, mixed>  $attributes
     *
     * @phpstan-ignore sineMaculaLaravel.modelBehaviour
     */
    public function __construct(array $attributes = [])
    {
        parent::__construct($attributes);

        $this->table = TableNames::get('roles');
    }

    /**
     * Return the connection the role table lives on: the configured
     * `authorization.connection`, else the instance's own, else the
     * application's default.
     *
     * Naming the connection is schema, so this is a framework hook rather than
     * model behaviour.
     *
     * @return string
     *
     * @phpstan-ignore sineMaculaLaravel.modelBehaviour
     */
    #[\Override]
    public function getConnectionName(): string
    {
        return AuthorizationConnection::resolve(parent::getConnectionName());
    }

    /**
     * The tenant that owns this role.
     *
     * A null morph pair marks the role as global (platform-level).
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphTo<\Illuminate\Database\Eloquent\Model, $this>
     */
    public function tenant(): MorphTo
    {
        return $this->morphTo('tenant');
    }

    /**
     * The attribute cast map.
     *
     * @return array<string, string>
     */
    #[\Override]
    protected function casts(): array
    {
        return [
            'name'        => 'string',
            'guard'       => 'string',
            'description' => 'string',
            'is_system'   => 'boolean',
            'parent_id'   => 'string',
            'rank'        => 'integer',
            'tenant_type' => 'string',
            'tenant_id'   => 'string',
        ];
    }

    /**
     * Human-readable label used in a name-validation exception message.
     *
     * @return string
     */
    protected function getAuthorizationNameKind(): string
    {
        return 'role';
    }

    /**
     * Construct the per-model exception raised when a protected mutation on a
     * system role is refused.
     *
     * @param  string  $operation
     * @return \Throwable
     */
    #[\Override]
    protected function systemProtectionException(string $operation): \Throwable
    {
        return new SystemRoleProtectedException(roleName: $this->systemProtectedName(), operation: $operation);
    }
}
