<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Models;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\Authorization\Events\RolePermissionGranted;
use SineMacula\Laravel\Authorization\Events\RolePermissionRevoked;
use SineMacula\Laravel\Authorization\Exceptions\UnknownPermissionException;
use SineMacula\Laravel\Authorization\Traits\ValidatesAuthorizationName;

/**
 * Eloquent model for role rows.
 *
 * Roles are named buckets of permissions shared across authorizable
 * identities. The `guard_name` column is nullable: a null value
 * marks the role as guard-agnostic (applies to every guard), a
 * concrete string scopes the role to a single guard.
 *
 * @property string $id
 * @property string $name
 * @property string|null $guard_name
 * @property string|null $description
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
class Role extends Model
{
    use HasUuids, ValidatesAuthorizationName;

    /**
     * The attributes that are mass assignable.
     *
     * @var list<string>
     */
    protected $fillable = [
        'name',
        'guard_name',
        'description',
    ];

    /**
     * Create a new Eloquent model instance.
     *
     * @param  array<string, mixed>  $attributes
     */
    public function __construct(array $attributes = [])
    {
        parent::__construct($attributes);

        /** @var string $table */
        $table       = config('authorization.tables.roles', 'roles');
        $this->table = $table;
    }

    /**
     * Permissions attached to this role.
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsToMany<\SineMacula\Laravel\Authorization\Models\Permission, $this>
     */
    public function permissions(): BelongsToMany
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Permission> $permissionModel */
        $permissionModel = config('authorization.models.permission', Permission::class);

        /** @var string $pivot */
        $pivot = config('authorization.tables.role_permissions', 'role_permissions');

        return $this->belongsToMany(
            related: $permissionModel,
            table: $pivot,
            foreignPivotKey: 'role_id',
            relatedPivotKey: 'permission_id',
        );
    }

    /**
     * Attach the given permission to this role.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission|string  $permission
     * @return static
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnknownPermissionException
     */
    public function givePermission(Permission|string $permission): static
    {
        $model = $this->resolvePermission($permission);

        $this->permissions()->syncWithoutDetaching([$model->getKey()]);

        if (isset($this->relations['permissions'])) {
            unset($this->relations['permissions']);
        }

        Event::dispatch(new RolePermissionGranted($this, $model));

        return $this;
    }

    /**
     * Detach the given permission from this role.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission|string  $permission
     * @return static
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnknownPermissionException
     */
    public function revokePermission(Permission|string $permission): static
    {
        $model = $this->resolvePermission($permission);

        $this->permissions()->detach($model->getKey());

        if (isset($this->relations['permissions'])) {
            unset($this->relations['permissions']);
        }

        Event::dispatch(new RolePermissionRevoked($this, $model));

        return $this;
    }

    /**
     * Replace this role's permission set with the supplied list.
     *
     * @param  array<int, \SineMacula\Laravel\Authorization\Models\Permission|string>  $permissions
     * @return static
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnknownPermissionException
     */
    public function syncPermissions(array $permissions): static
    {
        $ids = \array_values(\array_map(
            fn (Permission|string $permission): string => (string) $this->resolvePermission($permission)->getKey(),
            $permissions,
        ));

        $this->permissions()->sync($ids);

        if (isset($this->relations['permissions'])) {
            unset($this->relations['permissions']);
        }

        return $this;
    }

    /**
     * Determine whether this role carries the given permission.
     *
     * A held permission name is treated as an `fnmatch` pattern
     * against the asked name — so a role that holds `posts:*`
     * satisfies `hasPermission('posts:create')`, and a role that
     * holds `*:*` satisfies every check. The reverse direction does
     * not match: holding `posts:create` does not satisfy an asked
     * `posts:*`. Backslashes are compared literally via
     * `FNM_NOESCAPE`.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission|string  $permission
     * @return bool
     */
    public function hasPermission(Permission|string $permission): bool
    {
        $asked = $permission instanceof Permission ? $permission->name : $permission;

        foreach ($this->getPermissions() as $held) {
            if (\fnmatch($held, $asked, \FNM_NOESCAPE)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Return the names of every permission attached to this role.
     *
     * @return array<int, string>
     */
    public function getPermissions(): array
    {
        /** @var \Illuminate\Database\Eloquent\Collection<int, \SineMacula\Laravel\Authorization\Models\Permission> $permissions */
        $permissions = $this->permissions;

        $names = $permissions->map(static fn (Permission $permission): string => $permission->name)->all();

        return \array_values(\array_unique($names));
    }

    // ------------------------------------------------------------------
    // Spatie-compatible aliases
    // ------------------------------------------------------------------

    /**
     * Spatie alias for the canonical `givePermission()` helper.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission|string  $permission
     * @return static
     */
    public function givePermissionTo(Permission|string $permission): static
    {
        return $this->givePermission($permission);
    }

    /**
     * Spatie alias for the canonical `revokePermission()` helper.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission|string  $permission
     * @return static
     */
    public function revokePermissionTo(Permission|string $permission): static
    {
        return $this->revokePermission($permission);
    }

    /**
     * Spatie alias for the canonical `hasPermission()` helper.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission|string  $permission
     * @return bool
     */
    public function hasPermissionTo(Permission|string $permission): bool
    {
        return $this->hasPermission($permission);
    }

    /**
     * Spatie alias for the canonical `getPermissions()` helper.
     *
     * @return array<int, string>
     */
    public function getPermissionNames(): array
    {
        return $this->getPermissions();
    }

    /**
     * Resolve a permission identifier to a model instance.
     *
     * Mirrors `HasPermissions::resolvePermission()` so a role string
     * lookup honours the same guard-agnostic precedence rules.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission|string  $permission
     * @return \SineMacula\Laravel\Authorization\Models\Permission
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnknownPermissionException
     */
    protected function resolvePermission(Permission|string $permission): Permission
    {
        if ($permission instanceof Permission) {
            return $permission;
        }

        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Permission> $class */
        $class = config('authorization.models.permission', Permission::class);
        /** @var string $guard */
        $guard = config('authorization.defaults.guard', 'web');

        /** @var \SineMacula\Laravel\Authorization\Models\Permission|null $model */
        $model = $class::query()
            ->where('name', $permission)
            ->where(static function ($query) use ($guard): void {
                $query->where('guard_name', $guard)->orWhereNull('guard_name');
            })
            ->orderByRaw('guard_name IS NULL')
            ->first();

        if ($model === null) {
            throw new UnknownPermissionException($permission);
        }

        return $model;
    }

    /**
     * Human-readable label used in a name-validation exception
     * message.
     *
     * @return string
     */
    protected function getAuthorizationNameKind(): string
    {
        return 'role';
    }
}
