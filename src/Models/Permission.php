<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Models;

use Illuminate\Database\Eloquent\Attributes\ObservedBy;
use Illuminate\Database\Eloquent\Attributes\ScopedBy;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use SineMacula\Laravel\Authorization\Concerns\HasSystemProtection;
use SineMacula\Laravel\Authorization\Concerns\ValidatesAuthorizationName;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Database\LiveGrants;
use SineMacula\Laravel\Authorization\Exceptions\SystemPermissionProtectedException;
use SineMacula\Laravel\Authorization\Models\Pivots\RolePermission;
use SineMacula\Laravel\Authorization\Observers\PermissionObserver;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;

/**
 * Eloquent model for permission rows.
 *
 * Permissions are atomic action strings that can be granted directly to an
 * identity or inherited via a role. The `guard` column is nullable: a null
 * value marks the permission as guard-agnostic (applies to every guard), a
 * concrete string scopes it to a single guard. The `is_system` flag marks
 * platform-shipped permissions as protected: deleting, editing or clearing the
 * flag of a persisted `is_system = true` row raises
 * `SystemPermissionProtectedException` unless `forceSystem()` is invoked to
 * unlock the next operation on the instance.
 *
 * @property string $id
 * @property string $name
 * @property string|null $guard
 * @property string|null $description
 * @property string|null $category
 * @property bool $is_system
 * @property string|null $tenant_type
 * @property string|null $tenant_id
 *
 * @inheritable
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
#[ObservedBy(PermissionObserver::class)]
#[ScopedBy(TenantScope::class)]
class Permission extends Model
{
    use HasSystemProtection, HasUuids, ValidatesAuthorizationName;

    /** @var list<string> Attributes that are mass assignable. */
    protected $fillable = [
        'name',
        'guard',
        'description',
        'category',
        'is_system',
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

        /** @var string $table */
        $table       = config('authorization.tables.permissions', 'permissions');
        $this->table = $table;
    }

    /**
     * Return the connection the permission table lives on: the configured
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

    // ------------------------------------------------------------------ Tenant
    // ownership
    // ------------------------------------------------------------------

    /**
     * The tenant that owns this permission.
     *
     * A null morph pair marks the permission as global (platform-level).
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphTo<\Illuminate\Database\Eloquent\Model, $this>
     */
    public function tenant(): MorphTo
    {
        return $this->morphTo('tenant');
    }

    // ------------------------------------------------------------------ Role
    // relation
    // ------------------------------------------------------------------

    /**
     * Roles that carry this permission.
     *
     * The inverse of `Role::permissions()`: the same pivot table, the same
     * columns and the same `RolePermission` pivot model, so an `attach(...)` or
     * `sync(...)` from the permission side runs through the pivot's `saving`
     * hook and the guard-parity invariant it enforces. A role whose grant of
     * the permission has expired is left out.
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @formatter:off
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsToMany<\SineMacula\Laravel\Authorization\Models\Role, $this,
     *     \SineMacula\Laravel\Authorization\Models\Pivots\RolePermission, 'pivot'>
     *
     * @formatter:on
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     */
    public function roles(): BelongsToMany
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Role> $roleModel */
        $roleModel = config('authorization.models.role', Role::class);

        /** @var string $pivot */
        $pivot = config('authorization.tables.role_permissions', 'role_permissions');

        return $this->belongsToMany(
            related: $roleModel,
            table: $pivot,
            foreignPivotKey: 'permission_id',
            relatedPivotKey: 'role_id',
        )->using(RolePermission::class)
            ->withPivot('expires_at')
            ->where(static function (Builder $query) use ($pivot): void {
                LiveGrants::only($query, $pivot);
            });
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
            'category'    => 'string',
            'is_system'   => 'boolean',
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
        return 'permission';
    }

    /**
     * Construct the per-model exception raised when a protected mutation on a
     * system permission is refused.
     *
     * @param  string  $operation
     * @return \Throwable
     */
    #[\Override]
    protected function systemProtectionException(string $operation): \Throwable
    {
        return new SystemPermissionProtectedException(permissionName: $this->systemProtectedName(), operation: $operation);
    }
}
