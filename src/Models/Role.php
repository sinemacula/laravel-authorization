<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\Authorization\Events\RoleCreated;
use SineMacula\Laravel\Authorization\Events\RoleDeleted;
use SineMacula\Laravel\Authorization\Events\RolePermissionGranted;
use SineMacula\Laravel\Authorization\Events\RolePermissionRevoked;
use SineMacula\Laravel\Authorization\Events\RoleUpdated;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantColumnsException;
use SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException;
use SineMacula\Laravel\Authorization\Exceptions\SystemRoleProtectedException;
use SineMacula\Laravel\Authorization\Exceptions\UnknownPermissionException;
use SineMacula\Laravel\Authorization\Exceptions\UnknownRoleException;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\GuardScopedLookup;
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
 * @property string|null $parent_id
 * @property int|null $rank
 * @property string|null $tenant_type
 * @property string|null $tenant_id
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
        'parent_id',
        'rank',
        'tenant_type',
        'tenant_id',
    ];

    /**
     * The attribute casts.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'is_system' => 'boolean',
        'rank'      => 'integer',
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

        $model = GuardScopedLookup::queryForGuard($class, $name, $guard)->first();

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

    // ------------------------------------------------------------------
    // Tenant ownership
    // ------------------------------------------------------------------

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
     * Determine whether this role is global (not owned by any tenant).
     *
     * @return bool
     */
    public function isGlobal(): bool
    {
        return $this->tenant_type === null;
    }

    /**
     * Determine whether this role is owned by a tenant.
     *
     * @return bool
     */
    public function isTenantOwned(): bool
    {
        return $this->tenant_type !== null;
    }

    /**
     * Scope the query to rows owned by the given tenant.
     *
     * Delegates morph-pair extraction to
     * `TenantScope::extractTenantPair()` so the global scope and
     * this local scope share a single owner for the acceptance
     * rules — refuses any tenant that is neither a Model nor an
     * `AuthorizableTenant` implementer with a typed exception.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<static>  $query
     * @param  object  $tenant
     * @return \Illuminate\Database\Eloquent\Builder<static>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException
     */
    public function scopeForTenant(Builder $query, object $tenant): Builder
    {
        [$morphType, $morphId] = TenantScope::extractTenantPair($tenant);

        return $query->where($this->getTable() . '.tenant_type', $morphType)
            ->where($this->getTable() . '.tenant_id', $morphId);
    }

    /**
     * Scope the query to global rows only (tenant columns are null).
     *
     * @param  \Illuminate\Database\Eloquent\Builder<static>  $query
     * @return \Illuminate\Database\Eloquent\Builder<static>
     */
    public function scopeGlobalOnly(Builder $query): Builder
    {
        // `whereNull` is declared as `@method static` on the Eloquent
        // Builder docblock; PHPStan flags the dynamic instance call
        // as `staticMethod.dynamicCall` even though runtime dispatch
        // is genuinely dynamic. The same pattern is used in
        // `GuardScopedLookup` — a docblock-soup artefact, not an
        // unsafe call.
        // @phpstan-ignore staticMethod.dynamicCall
        return $query->whereNull($this->getTable() . '.tenant_type');
    }

    // ------------------------------------------------------------------
    // Hierarchy relations and helpers
    // ------------------------------------------------------------------

    /**
     * The parent role in the hierarchy.
     *
     * A null `parent_id` marks this role as a root (no parent).
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsTo<self, $this>
     */
    public function parent(): BelongsTo
    {
        return $this->belongsTo(static::class, 'parent_id');
    }

    /**
     * The direct children of this role in the hierarchy.
     *
     * @return \Illuminate\Database\Eloquent\Relations\HasMany<self, $this>
     */
    public function children(): HasMany
    {
        return $this->hasMany(static::class, 'parent_id');
    }

    /**
     * Return all ancestor roles ordered from root to immediate parent.
     *
     * Walks up the parent chain eagerly loading each level. Includes
     * cycle detection — if a visited role is encountered a second
     * time, the chain is broken and a
     * `RoleHierarchyCycleException` is thrown carrying the
     * offending role's name and the name of the parent that would
     * close the cycle.
     *
     * @return \Illuminate\Support\Collection<int, self>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    public function ancestors(): Collection
    {
        $ancestors = new Collection;
        $visited   = [];
        $current   = $this;

        while ($current->parent_id !== null) {
            if (isset($visited[$current->parent_id])) {
                /** @var static|null $proposedParent */
                $proposedParent = static::query()->find($current->parent_id);
                /** @var string $parentId */
                $parentId     = $current->parent_id;
                $proposedName = $proposedParent === null ? $parentId : $proposedParent->name;

                throw new RoleHierarchyCycleException(roleName: $this->name, proposedParentName: $proposedName);
            }

            $visited[$current->parent_id] = true;

            /** @var self|null $parent */
            $parent = $current->parent;

            if ($parent === null) {
                break;
            }

            $ancestors->prepend($parent);
            $current = $parent;
        }

        return $ancestors->values();
    }

    /**
     * Return all descendant roles (breadth-first).
     *
     * Carries a visited set keyed by primary key so a corrupted
     * hierarchy (cycle written via raw SQL, a race between two
     * concurrent `parent_id` saves, FK enforcement disabled) does
     * not turn the walk into a runaway loop. A re-encountered node
     * raises `RoleHierarchyCycleException` — matching the
     * ancestors-walk behaviour so callers have one exception to
     * catch regardless of direction.
     *
     * @return \Illuminate\Support\Collection<int, self>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    public function descendants(): Collection
    {
        $descendants = new Collection;
        $queue       = $this->children()->get()->all();

        /** @var string $selfKey */
        $selfKey = $this->getKey();
        $visited = [$selfKey => true];

        while ($queue !== []) {
            /** @var self $node */
            $node = \array_shift($queue);

            /** @var string $nodeId */
            $nodeId = $node->getKey();

            if (isset($visited[$nodeId])) {
                throw new RoleHierarchyCycleException(roleName: $this->name, proposedParentName: $node->name);
            }

            $visited[$nodeId] = true;
            $descendants->push($node);

            foreach ($node->children()->get() as $child) {
                $queue[] = $child;
            }
        }

        return $descendants->values();
    }

    /**
     * Determine whether this role is an ancestor of the given role.
     *
     * Delegates to the other role's `ancestors()` walk so cycle
     * detection has a single owner — any corrupted chain raises
     * `RoleHierarchyCycleException` from `ancestors()` rather than
     * looping forever.
     *
     * @param  self  $role
     * @return bool
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    public function isAncestorOf(self $role): bool
    {
        /** @var string $selfKey */
        $selfKey = $this->getKey();

        foreach ($role->ancestors() as $ancestor) {
            /** @var string $ancestorKey */
            $ancestorKey = $ancestor->getKey();

            if ($ancestorKey === $selfKey) {
                return true;
            }
        }

        return false;
    }

    /**
     * Determine whether this role is a descendant of the given role.
     *
     * @param  self  $role
     * @return bool
     */
    public function isDescendantOf(self $role): bool
    {
        return $role->isAncestorOf($this);
    }

    // ------------------------------------------------------------------
    // Rank helpers
    // ------------------------------------------------------------------

    /**
     * Determine whether this role carries a rank value.
     *
     * Unranked roles (`rank === null`) are not subject to
     * rank-based seniority checks.
     *
     * @return bool
     */
    public function isRanked(): bool
    {
        return $this->rank !== null;
    }

    /**
     * Determine whether this role outranks the given role.
     *
     * A lower numeric rank is more senior (0 = most senior). Both
     * roles must be ranked; if either is unranked the comparison is
     * undefined and the method returns false.
     *
     * @param  self  $other
     * @return bool
     */
    public function outranks(self $other): bool
    {
        if (!$this->isRanked() || !$other->isRanked()) {
            return false;
        }

        /** @var int $thisRank */
        $thisRank = $this->rank;

        /** @var int $otherRank */
        $otherRank = $other->rank;

        return $thisRank < $otherRank;
    }

    /**
     * Determine whether this role outranks or equals the given role.
     *
     * Same semantics as `outranks()` but uses `<=` (equal rank
     * satisfies the check). Both roles must be ranked; if either is
     * unranked the method returns false.
     *
     * @param  self  $other
     * @return bool
     */
    public function outranksOrEquals(self $other): bool
    {
        if (!$this->isRanked() || !$other->isRanked()) {
            return false;
        }

        /** @var int $thisRank */
        $thisRank = $this->rank;

        /** @var int $otherRank */
        $otherRank = $other->rank;

        return $thisRank <= $otherRank;
    }

    // ------------------------------------------------------------------
    // Permission management
    // ------------------------------------------------------------------

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
     * Return the names of every permission this role holds.
     *
     * When `authorization.hierarchy.enabled` is true (the default),
     * this includes the deduplicated union of the role's own direct
     * permissions and all permissions inherited from ancestor roles.
     * When hierarchy is disabled, only directly attached permissions
     * are returned.
     *
     * @return array<int, string>
     */
    public function getPermissions(): array
    {
        /** @var \Illuminate\Database\Eloquent\Collection<int, \SineMacula\Laravel\Authorization\Models\Permission> $permissions */
        $permissions = $this->permissions;

        $names = $permissions->map(static fn (Permission $permission): string => $permission->name)->all();

        /** @var bool $hierarchyEnabled */
        $hierarchyEnabled = config('authorization.hierarchy.enabled', true);

        if ($hierarchyEnabled && $this->parent_id !== null) {
            foreach ($this->ancestors() as $ancestor) {
                /** @var \Illuminate\Database\Eloquent\Collection<int, \SineMacula\Laravel\Authorization\Models\Permission> $ancestorPermissions */
                $ancestorPermissions = $ancestor->permissions;

                foreach ($ancestorPermissions as $ancestorPermission) {
                    $names[] = $ancestorPermission->name;
                }
            }
        }

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
     * into the package's typed CRUD events, plus the hierarchy
     * cycle-detection guard on `saving`. System-protection
     * hooks (`deleting`, `updating` guard, `saved` bypass reset)
     * are registered by `HasSystemProtection::bootHasSystemProtection()`.
     *
     * @return void
     */
    protected static function booted(): void
    {
        static::addGlobalScope(new TenantScope);

        static::saving(static function (self $role): void {
            // Enforce the both-or-neither tenant ownership invariant
            // before any hierarchy check — a row with only one of
            // `tenant_type` / `tenant_id` set would be invisible to
            // the `TenantScope` global filter and to
            // `scopeForTenant` / `scopeGlobalOnly`, silently
            // orphaning the data. Fail loudly on save.
            if (($role->tenant_type === null) !== ($role->tenant_id === null)) {
                throw new InvalidTenantColumnsException(modelKind: 'role', missingColumn: $role->tenant_type === null ? 'tenant_type' : 'tenant_id');
            }

            if ($role->parent_id === null) {
                return;
            }

            // Self-referential check.
            if ($role->exists && $role->parent_id === $role->getKey()) {
                throw new RoleHierarchyCycleException(roleName: $role->name, proposedParentName: $role->name);
            }

            // If the role already exists, verify the proposed parent
            // is not already a descendant (which would form a cycle).
            if ($role->exists && $role->isDirty('parent_id')) {
                $descendants = $role->descendants();

                foreach ($descendants as $descendant) {
                    if ($descendant->getKey() === $role->parent_id) {
                        /** @var self|null $proposedParent */
                        $proposedParent = static::query()->find($role->parent_id);
                        $proposedName   = $proposedParent?->name ?? $role->parent_id;

                        throw new RoleHierarchyCycleException(roleName: $role->name, proposedParentName: $proposedName);
                    }
                }
            }
        });

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
