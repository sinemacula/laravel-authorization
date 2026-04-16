<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\Authorization\Events\PermissionCreated;
use SineMacula\Laravel\Authorization\Events\PermissionDeleted;
use SineMacula\Laravel\Authorization\Events\PermissionUpdated;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantColumnsException;
use SineMacula\Laravel\Authorization\Exceptions\SystemPermissionProtectedException;
use SineMacula\Laravel\Authorization\Exceptions\UnknownPermissionException;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\GuardScopedLookup;
use SineMacula\Laravel\Authorization\Traits\HasSystemProtection;
use SineMacula\Laravel\Authorization\Traits\ValidatesAuthorizationName;

/**
 * Eloquent model for permission rows.
 *
 * Permissions are atomic action strings that can be granted directly
 * to an identity or inherited via a role. The `guard_name` column is
 * nullable: a null value marks the permission as guard-agnostic
 * (applies to every guard), a concrete string scopes it to a single
 * guard. The `is_system` flag marks platform-shipped permissions as
 * delete-protected: deletion or a rename of an `is_system = true`
 * row raises `SystemPermissionProtectedException` unless
 * `forceSystem()` is invoked to unlock the next operation on the
 * instance.
 *
 * @property string $id
 * @property string $name
 * @property string|null $guard_name
 * @property string|null $description
 * @property string|null $category
 * @property bool $is_system
 * @property string|null $tenant_type
 * @property string|null $tenant_id
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
class Permission extends Model
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
        'category',
        'is_system',
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
    ];

    /**
     * Pre-save attribute snapshot captured on `updating` and
     * consumed by the `updated` listener so `PermissionUpdated`
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
        $table       = config('authorization.tables.permissions', 'permissions');
        $this->table = $table;
    }

    // ------------------------------------------------------------------
    // Tenant ownership
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

    /**
     * Determine whether this permission is global (not owned by any tenant).
     *
     * @return bool
     */
    public function isGlobal(): bool
    {
        return $this->tenant_type === null;
    }

    /**
     * Determine whether this permission is owned by a tenant.
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
     * rules — refuses any tenant that is neither a Model nor a
     * `TenantIdentifier` implementer with a typed exception.
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
    // Role relation
    // ------------------------------------------------------------------

    /**
     * Roles that carry this permission.
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsToMany<\SineMacula\Laravel\Authorization\Models\Role, $this>
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
        );
    }

    /**
     * Resolve a permission by name under the supplied guard,
     * favouring guard-specific rows over guard-agnostic rows.
     *
     * Centralises the guard-precedence query shared by
     * `HasPermissions::resolvePermission()` and
     * `Role::resolvePermission()` — a single owner for the
     * guard-agnostic disjunction so evolution of the matching
     * rules happens in one place (see issue #55). Consumers
     * calling `$class::resolveByName(...)` where `$class` is
     * read from `authorization.models.permission` get correct
     * late-static-binding against their swapped model.
     *
     * @param  string  $name
     * @param  string|null  $guard
     * @return self
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnknownPermissionException
     */
    public static function resolveByName(string $name, ?string $guard = null): self
    {
        if ($guard === null) {
            /** @var string $guard */
            $guard = config('authorization.defaults.guard', 'web');
        }

        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Permission> $class */
        $class = config('authorization.models.permission', static::class);

        $model = GuardScopedLookup::queryForGuard($class, $name, $guard)->first();

        if ($model === null) {
            throw new UnknownPermissionException($name);
        }

        return $model;
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
        static::addGlobalScope(new TenantScope);

        static::saving(static function (self $permission): void {
            // Enforce the both-or-neither tenant ownership invariant
            // so a half-set row cannot be persisted — it would be
            // invisible to the `TenantScope` global filter and to
            // `scopeForTenant` / `scopeGlobalOnly`, silently
            // orphaning the data.
            if (($permission->tenant_type === null) !== ($permission->tenant_id === null)) {
                throw new InvalidTenantColumnsException(modelKind: 'permission', missingColumn: $permission->tenant_type === null ? 'tenant_type' : 'tenant_id');
            }
        });

        static::updating(static function (self $permission): void {
            $snapshot = [];

            foreach (\array_keys($permission->getDirty()) as $key) {
                $snapshot[$key] = $permission->getOriginal($key);
            }

            $permission->beforeChangeSnapshot = $snapshot;
        });

        static::created(static function (self $permission): void {
            Event::dispatch(new PermissionCreated($permission));
        });

        static::updated(static function (self $permission): void {
            Event::dispatch(new PermissionUpdated($permission, [
                'before' => $permission->beforeChangeSnapshot,
                'after'  => $permission->getChanges(),
            ]));

            $permission->beforeChangeSnapshot = [];
        });

        static::deleted(static function (self $permission): void {
            Event::dispatch(new PermissionDeleted($permission));
        });
    }

    /**
     * Human-readable label used in a name-validation exception
     * message.
     *
     * @return string
     */
    protected function getAuthorizationNameKind(): string
    {
        return 'permission';
    }

    /**
     * Return the attribute names whose dirty state triggers the
     * system-protection guard on `updating`. For permissions,
     * only `name` changes are protected.
     *
     * @return list<string>
     */
    protected function systemProtectedFields(): array
    {
        return ['name'];
    }

    /**
     * Construct the per-model exception raised when a protected
     * mutation on a system permission is refused.
     *
     * @param  string  $operation
     * @return \Throwable
     */
    protected function systemProtectionException(string $operation): \Throwable
    {
        // Use the ORIGINAL name — on a rename, `getAttribute('name')`
        // already reflects the mutated value. Audit consumers want
        // "which permission was targeted" (the canonical persisted
        // name), not "what the attempted rename would produce."
        /** @var string $permissionName */
        $permissionName = $this->getOriginal('name', $this->getAttribute('name'));

        return new SystemPermissionProtectedException(permissionName: $permissionName, operation: $operation);
    }
}
