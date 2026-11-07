<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Administration;

use Illuminate\Database\Eloquent\Collection as EloquentCollection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphToMany;
use SineMacula\Laravel\Authorization\Contracts\SupportsPermissions;
use SineMacula\Laravel\Authorization\Contracts\SupportsRoles;
use SineMacula\Laravel\Authorization\Database\LiveGrants;
use SineMacula\Laravel\Authorization\Database\UtcDateTime;
use SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\HeldPermissions;
use SineMacula\Laravel\Authorization\Support\RoleGraph;
use SineMacula\Laravel\Authorization\Support\SubjectGrants;

/**
 * How long a subject holds a permission in the current scope, through its
 * grants, for the possession route of a delegated grant (N77): until the latest
 * any grant that carries the permission lasts.
 *
 * The grants are those the decision resolves in the scope in place (its tenant
 * chain, whether it stands below its tenant, and its application, see
 * `TenantChain`), live now, read on the write connection: the subject's, and
 * its identity's when the identity grants to it. A grant carries the permission
 * when the name it grants covers it by the wildcard rules (see
 * `HeldPermissions`), so holding `posts:*` carries `posts:edit`. A direct grant
 * lasts until it expires; a role's lasts until the earlier of the role's grant
 * and the role's own grant of the permission, its ancestors' included when the
 * hierarchy is enabled, as far as the tenant scope shows them. A chain of roles
 * that cannot be read carries nothing, so a lifetime it cannot prove is never
 * claimed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class HeldLifetime
{
    /**
     * Return the Unix time until which the subject holds the permission in the
     * current scope, `PHP_INT_MAX` for a grant that never expires, or null when
     * it does not hold it, or while it or its identity is inactive.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  string  $permission
     * @return int|null
     */
    public static function of(Subject $subject, string $permission): ?int
    {
        if (SubjectGrants::isInactive($subject)) {
            return null;
        }

        $until = null;

        foreach ([$subject->subject, SubjectGrants::grantingIdentity($subject)] as $grantee) {
            if (!$grantee instanceof Model) {
                continue;
            }

            $until = self::later($until, self::direct($grantee, $permission), self::throughRoles($grantee, $permission));
        }

        return $until;
    }

    /**
     * Return until when the grantee's direct grants carry the permission, or
     * null when none does.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $grantee
     * @param  string  $permission
     * @return int|null
     */
    private static function direct(Model $grantee, string $permission): ?int
    {
        if (!$grantee instanceof SupportsPermissions || !\method_exists($grantee, 'permissions')) {
            return null;
        }

        $until = null;

        foreach (self::held($grantee->permissions()) as $held) {
            if (!self::carries($held->getAttribute('name'), $permission)) {
                continue;
            }

            $until = self::later($until, self::expiryOf($held));
        }

        return $until;
    }

    /**
     * Return until when the grantee's roles carry the permission, or null when
     * none does or their chain cannot be read.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $grantee
     * @param  string  $permission
     * @return int|null
     */
    private static function throughRoles(Model $grantee, string $permission): ?int
    {
        if (!$grantee instanceof SupportsRoles || !\method_exists($grantee, 'roles')) {
            return null;
        }

        /** @var list<\SineMacula\Laravel\Authorization\Models\Role> $roles */
        $roles = \array_values(self::held($grantee->roles())->all());

        try {
            $chains = self::chains($roles);
        } catch (RoleHierarchyCycleException) {
            return null;
        }

        $carried = self::carried(\array_values(\array_unique(\array_merge([], ...\array_values($chains)))), $permission);
        $until   = null;

        foreach ($roles as $role) {
            $carrying = \array_intersect_key($carried, \array_flip($chains[$role->id]));

            $until = self::later($until, $carrying === [] ? null : \min(self::expiryOf($role), \max($carrying)));
        }

        return $until;
    }

    /**
     * Return the keys each role carries the permissions of, keyed by the role:
     * the role's own, and its ancestors' the tenant scope shows when the
     * hierarchy is enabled.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Models\Role>  $roles
     * @return array<string, list<string>>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     */
    private static function chains(array $roles): array
    {
        /** @var bool $hierarchy */
        $hierarchy = config('authorization.hierarchy.enabled', true);
        $ancestors = $hierarchy ? RoleGraph::ancestorsOf($roles) : [];
        $chains    = [];

        foreach ($roles as $role) {
            $chains[$role->id] = [$role->id, ...\array_map(static fn (Role $ancestor): string => $ancestor->id, $ancestors[$role->id] ?? [])];
        }

        return $chains;
    }

    /**
     * Return, for each of the roles that grants itself a permission covering
     * the one given, live, until when the latest such grant lasts, keyed by the
     * role, in one query.
     *
     * @param  list<string>  $roles
     * @param  string  $permission
     * @return array<string, int>
     */
    private static function carried(array $roles, string $permission): array
    {
        if ($roles === []) {
            return [];
        }

        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Permission> $class */
        $class = config('authorization.models.permission', Permission::class);

        /** @var string $pivot */
        $pivot = config('authorization.tables.role_permissions', 'role_permissions');
        $model = new $class;
        $query = $class::query()->useWritePdo()->join($pivot, $pivot . '.permission_id', '=', $model->getQualifiedKeyName())->whereIn($pivot . '.role_id', $roles);

        $carried = [];

        $columns = [$pivot . '.role_id as role_id', $model->qualifyColumn('name') . ' as name', $pivot . '.expires_at as expires_at'];

        foreach (LiveGrants::only($query, $pivot)->toBase()->get($columns) as $row) {
            /** @var array{role_id: string, name: string, expires_at: string|null} $read */
            $read = (array) $row;

            if (!self::carries($read['name'], $permission)) {
                continue;
            }

            $until = UtcDateTime::toUtc($read['expires_at'])?->getTimestamp() ?? \PHP_INT_MAX;

            $carried[$read['role_id']] = \max($carried[$read['role_id']] ?? 0, $until);
        }

        return $carried;
    }

    /**
     * Read the live grants of the relation, with their expiry, on the write
     * connection.
     *
     * @param  \Illuminate\Database\Eloquent\Relations\MorphToMany<\Illuminate\Database\Eloquent\Model, \Illuminate\Database\Eloquent\Model>  $grants
     * @return \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model>
     */
    private static function held(MorphToMany $grants): EloquentCollection
    {
        /** @var \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model> */
        return $grants->useWritePdo()->get(); // @phpstan-ignore method.notFound
    }

    /**
     * Determine whether a granted name carries the permission, by the wildcard
     * rules.
     *
     * @param  mixed  $granted
     * @param  string  $permission
     * @return bool
     */
    private static function carries(mixed $granted, string $permission): bool
    {
        return \is_string($granted) && HeldPermissions::match([$granted], $permission) !== null;
    }

    /**
     * Return until when a grant read through a relation lasts: its expiry, as a
     * Unix time, or `PHP_INT_MAX` for one that never expires.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $grant
     * @return int
     */
    private static function expiryOf(Model $grant): int
    {
        /** @var \Illuminate\Database\Eloquent\Model $pivot */
        $pivot = $grant->getRelation('pivot');

        return UtcDateTime::toUtc($pivot->getAttribute('expires_at'))?->getTimestamp() ?? \PHP_INT_MAX;
    }

    /**
     * Return the latest of the times given, or null when none is.
     *
     * @param  int|null  ...$times
     * @return int|null
     */
    private static function later(?int ...$times): ?int
    {
        $known = \array_filter($times, static fn (?int $time): bool => $time !== null);

        return $known === [] ? null : \max($known);
    }
}
