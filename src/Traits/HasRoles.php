<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Traits;

use Illuminate\Database\Eloquent\Relations\MorphToMany;
use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\Authorization\Events\RoleAssigned;
use SineMacula\Laravel\Authorization\Events\RoleRevoked;
use SineMacula\Laravel\Authorization\Exceptions\UnknownRoleException;
use SineMacula\Laravel\Authorization\Models\Role;

/**
 * Role membership trait for authorizable models.
 *
 * Provides assignment, revocation, synchronisation, and query helpers
 * for roles. Method names mirror the package's canonical API; Spatie
 * consumers can rely on the shipped aliases (`assignRole`,
 * `removeRole`, `syncRoles`, `hasRole`, `getRoleNames`) to migrate
 * without rewriting call sites.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-require-extends \Illuminate\Database\Eloquent\Model
 */
trait HasRoles // @phpstan-ignore trait.unused
{
    /**
     * Morph-to-many relation onto roles.
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphToMany<\SineMacula\Laravel\Authorization\Models\Role, static>
     */
    public function roles(): MorphToMany
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Role> $model */
        $model = config('authorization.models.role', Role::class);

        /** @var string $pivot */
        $pivot = config('authorization.tables.authorizable_roles', 'authorizable_roles');

        return $this->morphToMany(
            related: $model,
            name: 'authorizable',
            table: $pivot,
            foreignPivotKey: 'authorizable_id',
            relatedPivotKey: 'role_id',
        );
    }

    /**
     * Assign the given role to this identity.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @return static
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnknownRoleException
     */
    public function assignRole(Role|string $role): static
    {
        $model = $this->resolveRole($role);

        $this->roles()->syncWithoutDetaching([$model->getKey()]);

        if (isset($this->relations['roles'])) {
            unset($this->relations['roles']);
        }

        Event::dispatch(new RoleAssigned($this, $model));

        return $this;
    }

    /**
     * Revoke the given role from this identity.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @return static
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnknownRoleException
     */
    public function revokeRole(Role|string $role): static
    {
        $model = $this->resolveRole($role);

        $this->roles()->detach($model->getKey());

        if (isset($this->relations['roles'])) {
            unset($this->relations['roles']);
        }

        Event::dispatch(new RoleRevoked($this, $model));

        return $this;
    }

    /**
     * Replace this identity's roles with the supplied set.
     *
     * @param  array<int, \SineMacula\Laravel\Authorization\Models\Role|string>  $roles
     * @return static
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnknownRoleException
     */
    public function syncRoles(array $roles): static
    {
        $ids = \array_values(\array_map(
            fn (Role|string $role): string => (string) $this->resolveRole($role)->getKey(),
            $roles,
        ));

        $this->roles()->sync($ids);

        if (isset($this->relations['roles'])) {
            unset($this->relations['roles']);
        }

        return $this;
    }

    /**
     * Determine whether this identity has the given role.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @return bool
     */
    public function hasRole(Role|string $role): bool
    {
        $name = $role instanceof Role ? $role->name : $role;

        /** @var \Illuminate\Database\Eloquent\Collection<int, \SineMacula\Laravel\Authorization\Models\Role> $roles */
        $roles = $this->roles;

        foreach ($roles as $existing) {
            if ($existing->name === $name) {
                return true;
            }
        }

        return false;
    }

    /**
     * Return the names of every role assigned to this identity.
     *
     * @return array<int, string>
     */
    public function getRoles(): array
    {
        /** @var \Illuminate\Database\Eloquent\Collection<int, \SineMacula\Laravel\Authorization\Models\Role> $roles */
        $roles = $this->roles;

        $names = $roles->map(static fn (Role $role): string => $role->name)->all();

        return \array_values($names);
    }

    // ------------------------------------------------------------------
    // Spatie-compatible aliases
    // ------------------------------------------------------------------

    /**
     * Spatie alias for {@see self::revokeRole()}.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @return static
     */
    public function removeRole(Role|string $role): static
    {
        return $this->revokeRole($role);
    }

    /**
     * Spatie alias for {@see self::getRoles()}.
     *
     * @return array<int, string>
     */
    public function getRoleNames(): array
    {
        return $this->getRoles();
    }

    /**
     * Resolve a role identifier to a model instance.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
     * @return \SineMacula\Laravel\Authorization\Models\Role
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\UnknownRoleException
     */
    protected function resolveRole(Role|string $role): Role
    {
        if ($role instanceof Role) {
            return $role;
        }

        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Role> $class */
        $class = config('authorization.models.role', Role::class);
        /** @var string $guard */
        $guard = config('authorization.defaults.guard', 'web');

        /** @var \SineMacula\Laravel\Authorization\Models\Role|null $model */
        $model = $class::query()
            ->where('name', $role)
            ->where('guard_name', $guard)
            ->first();

        if ($model === null) {
            throw new UnknownRoleException($role);
        }

        return $model;
    }
}
