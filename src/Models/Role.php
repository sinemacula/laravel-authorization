<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Models;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\Authorization\Events\RoleCreated;
use SineMacula\Laravel\Authorization\Events\RoleDeleted;
use SineMacula\Laravel\Authorization\Events\RolePermissionGranted;
use SineMacula\Laravel\Authorization\Events\RolePermissionRevoked;
use SineMacula\Laravel\Authorization\Events\RoleUpdated;
use SineMacula\Laravel\Authorization\Exceptions\SystemRoleProtectedException;
use SineMacula\Laravel\Authorization\Exceptions\UnknownPermissionException;
use SineMacula\Laravel\Authorization\Traits\ValidatesAuthorizationName;

/**
 * Eloquent model for role rows.
 *
 * Roles are named buckets of permissions shared across authorizable
 * identities. The `guard_name` column is nullable: a null value
 * marks the role as guard-agnostic (applies to every guard), a
 * concrete string scopes the role to a single guard. The
 * `is_system` flag marks platform-shipped roles as
 * delete-protected: deletion or a rename of an `is_system = true`
 * row raises `SystemRoleProtectedException` unless
 * `forceSystem()` is invoked to unlock the next operation on the
 * instance.
 *
 * @property string $id
 * @property string $name
 * @property string|null $guard_name
 * @property string|null $description
 * @property bool $is_system
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
        'is_system',
    ];

    /**
     * The attribute casts.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'is_system' => 'boolean',
    ];

    /**
     * Per-instance escape-hatch flag. When true, the next delete
     * or rename bypasses the system-role protection and resets to
     * false on completion. Invoked via `forceSystem()` — never
     * persisted, never inherited across instances.
     *
     * @var bool
     */
    private bool $systemProtectionBypassed = false;

    /**
     * Pre-save attribute snapshot captured on `updating` and
     * consumed by the `updated` listener so `RoleUpdated`
     * carries a complete before/after diff. Reset after each
     * dispatch so a follow-up save observes a clean slate.
     *
     * @var array<string, mixed>
     */
    private array $beforeChangeSnapshot = [];

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
     * Unlock the next protected mutation (delete or rename) on
     * this instance. Returns `$this` for chaining:
     *
     *     $role->forceSystem()->delete();
     *
     * The bypass is **per-instance, single-use, and in-memory** —
     * it never persists to the database, never leaks across
     * instances (a `$role->fresh()` drops it), and resets to
     * false the moment the guard clause consults it.
     *
     * @return static
     */
    public function forceSystem(): static
    {
        $this->systemProtectionBypassed = true;

        return $this;
    }

    /**
     * Permissions attached to this role.
     *
     * The relation is bound to the `RolePermission` pivot so every
     * attachment path — the typed Role API, a direct
     * `$role->permissions()->attach(...)`, or a raw
     * `sync(...)` — runs through the pivot's `saving` hook and the
     * guard-parity invariant it enforces.
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
        )->using(RolePermission::class);
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
     * Each net attachment fires `RolePermissionGranted` and each
     * net detachment fires `RolePermissionRevoked`, so audit
     * consumers receive the same per-row signal they would for
     * `givePermission()` / `revokePermission()` calls and the
     * cache invalidation listener wired to those events keeps
     * the resolution cache coherent.
     *
     * @param  array<int, \SineMacula\Laravel\Authorization\Models\Permission|string>  $permissions
     * @return static
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnknownPermissionException
     */
    public function syncPermissions(array $permissions): static
    {
        $resolved = [];

        foreach ($permissions as $permission) {
            $model                               = $this->resolvePermission($permission);
            $resolved[(string) $model->getKey()] = $model;
        }

        $ids    = \array_keys($resolved);
        $result = $this->permissions()->sync($ids);

        if (isset($this->relations['permissions'])) {
            unset($this->relations['permissions']);
        }

        /** @var array{attached?: array<int, mixed>, detached?: array<int, mixed>, updated?: array<int, mixed>} $result */
        foreach ($result['attached'] ?? [] as $id) {
            Event::dispatch(new RolePermissionGranted($this, $resolved[(string) $id] ?? $this->resolvePermissionById((string) $id)));
        }

        foreach ($result['detached'] ?? [] as $id) {
            Event::dispatch(new RolePermissionRevoked($this, $this->resolvePermissionById((string) $id)));
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
     * Register the row-lifecycle listeners that translate
     * Eloquent's native `created` / `updated` / `deleted` events
     * into the package's typed CRUD events, and enforce the
     * system-role protection invariant on `deleting` / `updating`
     * before the row reaches the database.
     *
     * @return void
     */
    protected static function booted(): void
    {
        static::deleting(static function (self $role): void {
            $role->assertSystemProtectionAllows('delete');
        });

        static::updating(static function (self $role): void {
            if ($role->wasSystemRoleRenamed()) {
                $role->assertSystemProtectionAllows('rename');
            }

            $snapshot = [];

            foreach (\array_keys($role->getDirty()) as $key) {
                $snapshot[$key] = $role->getOriginal($key);
            }

            $role->beforeChangeSnapshot = $snapshot;
        });

        static::created(static function (self $role): void {
            Event::dispatch(new RoleCreated($role));
        });

        static::updated(static function (self $role): void {
            Event::dispatch(new RoleUpdated($role, [
                'before' => $role->beforeChangeSnapshot,
                'after'  => $role->getChanges(),
            ]));

            $role->beforeChangeSnapshot = [];
        });

        static::deleted(static function (self $role): void {
            Event::dispatch(new RoleDeleted($role));
        });

        // Clear the bypass flag after every completed save so it
        // cannot hop across an intervening non-protected mutation
        // (e.g. a description update) and silently unlock the next
        // rename or delete. `saved` fires after `updating` has had
        // a chance to consume the flag for a legitimate rename, so
        // this reset is strictly idempotent on that path.
        static::saved(static function (self $role): void {
            $role->systemProtectionBypassed = false;
        });
    }

    /**
     * Resolve a permission identifier to a model instance.
     *
     * Role rows carry their own `guard_name`; use it as the lookup
     * scope so a web-scoped role resolves permissions against the
     * web guard and an api-scoped role against the api guard.
     * Falls back to the package default when the role itself is
     * guard-agnostic (null `guard_name`). Delegates the query to
     * `Permission::resolveByName()` so both sides share one
     * implementation (see #55).
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

        return $class::resolveByName($permission, $this->guard_name);
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

    /**
     * Resolve a permission model by primary key, used by
     * `syncPermissions()` when the sync delta surfaces an ID
     * that was not part of the caller's input set (the
     * detachment list).
     *
     * @param  string  $id
     * @return \SineMacula\Laravel\Authorization\Models\Permission
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnknownPermissionException
     */
    private function resolvePermissionById(string $id): Permission
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Permission> $class */
        $class = config('authorization.models.permission', Permission::class);

        /** @var \SineMacula\Laravel\Authorization\Models\Permission|null $model */
        $model = $class::query()->whereKey($id)->first();

        if ($model === null) {
            throw new UnknownPermissionException($id);
        }

        return $model;
    }

    /**
     * Decide whether the supplied mutation is allowed against the
     * current instance. Consumes the bypass flag so a second
     * protected operation on the same instance re-arms the
     * protection.
     *
     * @param  string  $operation
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\SystemRoleProtectedException
     */
    private function assertSystemProtectionAllows(string $operation): void
    {
        if ((bool) $this->getAttribute('is_system') === false) {
            return;
        }

        if ($this->systemProtectionBypassed) {
            $this->systemProtectionBypassed = false;

            return;
        }

        // Use the ORIGINAL name — on a rename, `getAttribute('name')`
        // already reflects the mutated value. Audit consumers want
        // "which role was targeted" (the canonical persisted name),
        // not "what the attempted rename would produce."
        /** @var string $roleName */
        $roleName = $this->getOriginal('name', $this->getAttribute('name'));

        throw new SystemRoleProtectedException(roleName: (string) $roleName, operation: $operation);
    }

    /**
     * Test whether the pending update renames a system role.
     * Only rename operations go through the protection check;
     * description and guard_name bumps pass unconditionally.
     *
     * @return bool
     */
    private function wasSystemRoleRenamed(): bool
    {
        if (!(bool) $this->getAttribute('is_system')) {
            return false;
        }

        /** @var array<string, mixed> $dirty */
        $dirty = $this->getDirty();

        return \array_key_exists('name', $dirty);
    }
}
