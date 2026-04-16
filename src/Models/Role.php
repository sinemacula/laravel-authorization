<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Models;

use Illuminate\Database\Eloquent\Builder;
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
use SineMacula\Laravel\Authorization\Exceptions\UnknownRoleException;
use SineMacula\Laravel\Authorization\Traits\HasSystemProtection;
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
    use HasSystemProtection, HasUuids, ValidatesAuthorizationName;

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
     * Resolve a role by name under the supplied guard, favouring
     * guard-specific rows over guard-agnostic rows.
     *
     * Centralises the guard-precedence query shared by
     * `HasRoles::resolveRole()` and any direct static caller — a
     * single owner for the guard-agnostic disjunction so evolution
     * of the matching rules happens in one place (see issue #55
     * and #96). Consumers calling `$class::resolveByName(...)`
     * where `$class` is read from `authorization.models.role` get
     * correct late-static-binding against their swapped model.
     *
     * @param  string  $name
     * @param  string|null  $guard
     * @return self
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnknownRoleException
     */
    public static function resolveByName(string $name, ?string $guard = null): self
    {
        if ($guard === null) {
            /** @var string $guard */
            $guard = config('authorization.defaults.guard', 'web');
        }

        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Role> $class */
        $class = config('authorization.models.role', static::class);

        $model = self::queryForGuard($class, $name, $guard)->first();

        if ($model === null) {
            throw new UnknownRoleException($name);
        }

        return $model;
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
     * into the package's typed CRUD events. System-protection
     * hooks (`deleting`, `updating` guard, `saved` bypass reset)
     * are registered by `HasSystemProtection::bootHasSystemProtection()`.
     *
     * @return void
     */
    protected static function booted(): void
    {
        static::updating(static function (self $role): void {
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
     * Return the attribute names whose dirty state triggers the
     * system-protection guard on `updating`. For roles, only
     * `name` changes are protected.
     *
     * @return list<string>
     */
    protected function systemProtectedFields(): array
    {
        return ['name'];
    }

    /**
     * Construct the per-model exception raised when a protected
     * mutation on a system role is refused.
     *
     * @param  string  $operation
     * @return \Throwable
     */
    protected function systemProtectionException(string $operation): \Throwable
    {
        // Use the ORIGINAL name — on a rename, `getAttribute('name')`
        // already reflects the mutated value. Audit consumers want
        // "which role was targeted" (the canonical persisted name),
        // not "what the attempted rename would produce."
        /** @var string $roleName */
        $roleName = $this->getOriginal('name', $this->getAttribute('name'));

        return new SystemRoleProtectedException(roleName: (string) $roleName, operation: $operation);
    }

    /**
     * Build the guard-precedence query for the supplied role
     * name. Centralises the dynamic class-string handling so the
     * caller stays readable and the two unavoidable PHPStan
     * suppressions live in one place.
     *
     * The configured role model is instantiated through `new
     * $class` so PHPStan resolves the receiver as an Eloquent
     * `Model` instance — `newQuery()`, `where()`, and the closure
     * receiver type cleanly without ignores. The remaining two
     * suppressions on `orderByRaw()` and `orWhereNull()` exist
     * because Laravel declares those methods via `@method static`
     * annotations on `Illuminate\Database\Eloquent\Builder`, which
     * PHPStan flags as `staticMethod.dynamicCall` whenever they
     * appear inside an instance-method chain. They are runtime-
     * dynamic instance calls; the static-receiver shape is a
     * docblock artefact of Laravel's annotation soup, not the
     * actual call dispatch.
     *
     * @param  class-string<\SineMacula\Laravel\Authorization\Models\Role>  $class
     * @param  string  $name
     * @param  string  $guard
     * @return \Illuminate\Database\Eloquent\Builder<\SineMacula\Laravel\Authorization\Models\Role>
     */
    private static function queryForGuard(string $class, string $name, string $guard): Builder
    {
        $instance = new $class;

        // The chain ends in `orderByRaw()`, which Laravel declares
        // as `@method static` on Illuminate\Database\Eloquent\Builder.
        // PHPStan flags any dynamic call to such a method as
        // `staticMethod.dynamicCall` even though runtime dispatch is
        // genuinely dynamic instance dispatch on a Builder instance.
        // The same applies to `orWhereNull()` inside the closure
        // below. Both ignores are docblock-soup artefacts, not
        // unsafe calls.
        // @phpstan-ignore staticMethod.dynamicCall
        return $instance->newQuery()
            ->where('name', $name)
            ->where(static function (Builder $query) use ($guard): void {
                // @phpstan-ignore staticMethod.dynamicCall
                $query->where('guard_name', $guard)->orWhereNull('guard_name');
            })
            ->orderByRaw('guard_name IS NULL');
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
}
