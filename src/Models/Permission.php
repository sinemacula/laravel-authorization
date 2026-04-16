<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\Authorization\Events\PermissionCreated;
use SineMacula\Laravel\Authorization\Events\PermissionDeleted;
use SineMacula\Laravel\Authorization\Events\PermissionUpdated;
use SineMacula\Laravel\Authorization\Exceptions\SystemPermissionProtectedException;
use SineMacula\Laravel\Authorization\Exceptions\UnknownPermissionException;
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
 * @property bool $is_system
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
class Permission extends Model
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
     * or rename bypasses the system-permission protection and
     * resets to false on completion. Invoked via `forceSystem()` —
     * never persisted, never inherited across instances.
     *
     * @var bool
     */
    private bool $systemProtectionBypassed = false;

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

    /**
     * Unlock the next protected mutation (delete or rename) on
     * this instance. Returns `$this` for chaining:
     *
     *     $permission->forceSystem()->delete();
     *
     * The bypass is **per-instance, single-use, and in-memory** —
     * it never persists to the database, never leaks across
     * instances (a `$permission->fresh()` drops it), and resets to
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

        $model = self::queryForGuard($class, $name, $guard)->first();

        if ($model === null) {
            throw new UnknownPermissionException($name);
        }

        return $model;
    }

    /**
     * Register the row-lifecycle listeners that translate
     * Eloquent's native `created` / `updated` / `deleted` events
     * into the package's typed CRUD events, and enforce the
     * system-permission protection invariant on `deleting` /
     * `updating` before the row reaches the database.
     *
     * @return void
     */
    protected static function booted(): void
    {
        static::deleting(static function (self $permission): void {
            $permission->assertSystemProtectionAllows('delete');
        });

        static::updating(static function (self $permission): void {
            if ($permission->wasSystemPermissionRenamed()) {
                $permission->assertSystemProtectionAllows('rename');
            }

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

        // Clear the bypass flag after every completed save so it
        // cannot hop across an intervening non-protected mutation
        // (e.g. a description update) and silently unlock the next
        // rename or delete. `saved` fires after `updating` has had
        // a chance to consume the flag for a legitimate rename, so
        // this reset is strictly idempotent on that path.
        static::saved(static function (self $permission): void {
            $permission->systemProtectionBypassed = false;
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
     * Build the guard-precedence query for the supplied permission
     * name. Centralises the dynamic class-string handling so the
     * caller stays readable and the two unavoidable PHPStan
     * suppressions live in one place.
     *
     * The configured permission model is instantiated through `new
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
     * @param  class-string<\SineMacula\Laravel\Authorization\Models\Permission>  $class
     * @param  string  $name
     * @param  string  $guard
     * @return \Illuminate\Database\Eloquent\Builder<\SineMacula\Laravel\Authorization\Models\Permission>
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
     * Decide whether the supplied mutation is allowed against the
     * current instance. Consumes the bypass flag so a second
     * protected operation on the same instance re-arms the
     * protection.
     *
     * @param  string  $operation
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\SystemPermissionProtectedException
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
        // "which permission was targeted" (the canonical persisted
        // name), not "what the attempted rename would produce."
        /** @var string $permissionName */
        $permissionName = $this->getOriginal('name', $this->getAttribute('name'));

        throw new SystemPermissionProtectedException(permissionName: $permissionName, operation: $operation);
    }

    /**
     * Test whether the pending update renames a system permission.
     * Only rename operations go through the protection check;
     * description and guard_name bumps pass unconditionally.
     *
     * @return bool
     */
    private function wasSystemPermissionRenamed(): bool
    {
        if (!(bool) $this->getAttribute('is_system')) {
            return false;
        }

        /** @var array<string, mixed> $dirty */
        $dirty = $this->getDirty();

        return \array_key_exists('name', $dirty);
    }
}
