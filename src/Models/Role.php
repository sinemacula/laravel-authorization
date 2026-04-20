<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Models;

use Illuminate\Database\Eloquent\Attributes\ObservedBy;
use Illuminate\Database\Eloquent\Attributes\ScopedBy;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use SineMacula\Laravel\Authorization\Exceptions\SystemRoleProtectedException;
use SineMacula\Laravel\Authorization\Exceptions\UnknownRoleException;
use SineMacula\Laravel\Authorization\Observers\RoleObserver;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\GuardScopedLookup;
use SineMacula\Laravel\Authorization\Traits\HasRoleHierarchy;
use SineMacula\Laravel\Authorization\Traits\HasSystemProtection;
use SineMacula\Laravel\Authorization\Traits\ManagesPermissions;
use SineMacula\Laravel\Authorization\Traits\ValidatesAuthorizationName;

/**
 * Eloquent model for role rows — named buckets of permissions shared across
 * authorizable identities. Behaviour is composed from `HasRoleHierarchy`,
 * `ManagesPermissions`, `HasSystemProtection`, and the `RoleObserver` wired via
 * `#[ObservedBy]`.
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
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
#[ObservedBy(RoleObserver::class)]
#[ScopedBy(TenantScope::class)]
class Role extends Model
{
    use HasRoleHierarchy, HasSystemProtection, HasUuids, ManagesPermissions, ValidatesAuthorizationName;

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

    /** @var array<string, string> Attribute cast map. */
    protected $casts = [
        'is_system' => 'boolean',
        'rank'      => 'integer',
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
     * Resolve a role by name under the supplied guard, favouring guard-specific
     * rows over guard-agnostic rows.
     *
     * Centralises the guard-precedence query shared by
     * `HasRoles::resolveRole()` and any direct static caller — a single owner
     * for the guard-agnostic disjunction so evolution of the matching rules
     * happens in one place. Consumers calling `$class::resolveByName(...)`
     * where `$class` is read from `authorization.models.role` get correct
     * late-static-binding against their swapped model.
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

        $model = GuardScopedLookup::findForGuard($class, $name, $guard);

        if (!$model instanceof self) {
            throw new UnknownRoleException($name);
        }

        return $model;
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
     * Delegates morph-pair extraction to `TenantScope::extractTenantPair()` so
     * the global scope and this local scope share a single owner for the
     * acceptance rules — refuses any tenant that is neither a Model nor an
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
     * Return the attribute names whose dirty state triggers the
     * system-protection guard on `updating`. For roles, only `name` changes are
     * protected.
     *
     * @return list<string>
     */
    protected function systemProtectedFields(): array
    {
        return ['name'];
    }

    /**
     * Construct the per-model exception raised when a protected mutation on a
     * system role is refused.
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

        return new SystemRoleProtectedException(roleName: $roleName, operation: $operation);
    }
}
