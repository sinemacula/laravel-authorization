<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Administration;

use Illuminate\Database\Eloquent\Collection as EloquentCollection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphToMany;
use SineMacula\Laravel\Authorization\Config\ModelClasses;
use SineMacula\Laravel\Authorization\Config\SwitchConfigValidator;
use SineMacula\Laravel\Authorization\Config\TableNames;
use SineMacula\Laravel\Authorization\Contracts\SupportsPermissions;
use SineMacula\Laravel\Authorization\Contracts\SupportsPolicies;
use SineMacula\Laravel\Authorization\Contracts\SupportsRoles;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Database\GrantApplications;
use SineMacula\Laravel\Authorization\Database\LiveGrants;
use SineMacula\Laravel\Authorization\Database\UtcDateTime;
use SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\HeldPermissions;
use SineMacula\Laravel\Authorization\Support\RoleGraph;
use SineMacula\Laravel\Authorization\Support\SubjectGrants;

/**
 * How long a subject holds a permission, or a policy, in the current scope,
 * through its grants, for the possession and grantable routes of a delegated
 * grant (N77): until the latest any grant that carries it lasts.
 *
 * The grants are those the decision resolves in the scope in place (its tenant
 * chain, whether it stands below its tenant, and its application, see
 * `TenantChain`), live now, read on the write connection: the subject's, and
 * its identity's when the identity grants to it. A grant carries the permission
 * when the name it grants covers it by the wildcard rules (see
 * `HeldPermissions`), so holding `posts:*` carries `posts:edit`; a policy is
 * carried by its attachments. A direct grant or attachment lasts until it
 * expires; a role's lasts until the earlier of the role's grant and the role's
 * own grant of the permission, or attachment of the policy, its ancestors'
 * included when the hierarchy is enabled, as far as the tenant scope shows
 * them. A chain of roles that cannot be read carries nothing, so a lifetime it
 * cannot prove is never claimed.
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
        return self::ofEach($subject, [$permission])[$permission];
    }

    /**
     * Return, for each of the permissions, the Unix time until which the
     * subject holds it in the current scope, as `of()` reads it, keyed by the
     * permission, reading the subject's grants once for them all, so the cost
     * never grows with the permissions.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  list<string>  $permissions
     * @return array<array-key, int|null>
     */
    public static function ofEach(Subject $subject, array $permissions): array
    {
        return self::across(
            $subject,
            $permissions,
            static fn (Model $grantee): array => self::direct($grantee, $permissions),
            static fn (array $roles): array => self::carried($roles, $permissions),
        );
    }

    /**
     * Return the Unix time until which the policy with the key is attached to
     * the subject in the current scope, directly or through a role,
     * `PHP_INT_MAX` for an attachment that never expires, or null when it is
     * not attached, or while the subject or its identity is inactive.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  string  $policy
     * @return int|null
     */
    public static function ofPolicy(Subject $subject, string $policy): ?int
    {
        return self::across(
            $subject,
            [$policy],
            static fn (Model $grantee): array => [$policy => self::attached($grantee, $policy)],
            static fn (array $roles): array => [$policy => self::attachedToRoles($roles, $policy)],
        )[$policy];
    }

    /**
     * Return, for each of what is held, the latest lifetime the subject's
     * grantees hold it for through their direct grants and their roles, keyed
     * by what is held, each null while the subject or its identity is inactive.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  list<string>  $held
     * @param  \Closure(\Illuminate\Database\Eloquent\Model): array<array-key, int|null>  $direct
     * @param  \Closure(list<string>): array<array-key, array<string, int>>  $carried
     * @return array<array-key, int|null>
     */
    private static function across(Subject $subject, array $held, \Closure $direct, \Closure $carried): array
    {
        $until = \array_fill_keys($held, null);

        if (SubjectGrants::isInactive($subject)) {
            return $until;
        }

        foreach ([$subject->subject, SubjectGrants::grantingIdentity($subject)] as $grantee) {
            if (!$grantee instanceof Model) {
                continue;
            }

            $directly = $direct($grantee);
            $roles    = self::throughRoles($grantee, $held, $carried);

            foreach ($held as $name) {
                $until[$name] = self::later($until[$name], $directly[$name], $roles[$name] ?? null);
            }
        }

        return $until;
    }

    /**
     * Return, for each of the permissions, until when the grantee's direct
     * grants carry it, null when none does, keyed by the permission.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $grantee
     * @param  list<string>  $permissions
     * @return array<array-key, int|null>
     */
    private static function direct(Model $grantee, array $permissions): array
    {
        $until = \array_fill_keys($permissions, null);

        if (!$grantee instanceof SupportsPermissions || !\method_exists($grantee, 'permissions')) {
            return $until;
        }

        foreach (self::held($grantee->permissions()) as $held) {
            foreach ($permissions as $permission) {
                if (!self::carries($held->getAttribute('name'), $permission)) {
                    continue;
                }

                $until[$permission] = self::later($until[$permission], self::expiryOf($held));
            }
        }

        return $until;
    }

    /**
     * Return until when the policy with the key is attached to the grantee
     * directly, or null when it is not.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $grantee
     * @param  string  $policy
     * @return int|null
     */
    private static function attached(Model $grantee, string $policy): ?int
    {
        if (!$grantee instanceof SupportsPolicies || !\method_exists($grantee, 'policies')) {
            return null;
        }

        $until = null;

        foreach (self::held($grantee->policies()->whereKey($policy)) as $held) {
            $until = self::later($until, self::expiryOf($held));
        }

        return $until;
    }

    /**
     * Return, for each of what is held, until when the grantee's roles carry
     * it, as the callback reads it for them, keyed by what is held; none when
     * no role does or their chain cannot be read.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $grantee
     * @param  list<string>  $held
     * @param  \Closure(list<string>): array<array-key, array<string, int>>  $carried
     * @return array<array-key, int|null>
     */
    private static function throughRoles(Model $grantee, array $held, \Closure $carried): array
    {
        if (!$grantee instanceof SupportsRoles || !\method_exists($grantee, 'roles')) {
            return [];
        }

        /** @var list<\SineMacula\Laravel\Authorization\Models\Role> $roles */
        $roles = self::held($grantee->roles())->all();

        try {
            $chains = self::chains($roles);
        } catch (RoleHierarchyCycleException) {
            return [];
        }

        $carrying = $carried(\array_merge([], ...\array_values($chains)));
        $until    = [];

        foreach ($held as $name) {
            foreach ($roles as $role) {
                $carries = \array_intersect_key($carrying[$name] ?? [], \array_flip($chains[$role->id]));

                $until[$name] = self::later($until[$name] ?? null, $carries === [] ? null : \min(self::expiryOf($role), \max($carries)));
            }
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
        $hierarchy = SwitchConfigValidator::isEnabled('hierarchy');
        $ancestors = $hierarchy ? RoleGraph::ancestorsOf($roles) : [];
        $chains    = [];

        foreach ($roles as $role) {
            $chains[$role->id] = [$role->id, ...\array_map(static fn (Role $ancestor): string => $ancestor->id, $ancestors[$role->id] ?? [])];
        }

        return $chains;
    }

    /**
     * Return, for each of the permissions, and for each of the roles that
     * grants itself a permission covering it, live, until when the latest such
     * grant lasts, keyed by the permission, then by the role, in one query.
     *
     * @param  list<string>  $roles
     * @param  list<string>  $permissions
     * @return array<array-key, array<string, int>>
     */
    private static function carried(array $roles, array $permissions): array
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Permission> $class */
        $class = ModelClasses::get('permission');

        $pivot = TableNames::get('role_permissions');
        $model = new $class;
        $query = $class::query()->useWritePdo()->join($pivot, $pivot . '.permission_id', '=', $model->getQualifiedKeyName())->whereIn($pivot . '.role_id', $roles);

        $carried = [];

        $columns = [$pivot . '.role_id as role_id', $model->qualifyColumn('name'), $pivot . '.expires_at as expires_at'];

        foreach (LiveGrants::only($query, $pivot)->toBase()->get($columns) as $row) {
            /** @var array{role_id: string, name: string, expires_at: string|null} $read */
            $read  = (array) $row;
            $until = UtcDateTime::toUtc($read['expires_at'])?->getTimestamp() ?? \PHP_INT_MAX;

            foreach ($permissions as $permission) {
                if (!self::carries($read['name'], $permission)) {
                    continue;
                }

                $carried[$permission][$read['role_id']] = \max($carried[$permission][$read['role_id']] ?? $until, $until);
            }
        }

        return $carried;
    }

    /**
     * Return, for each of the roles the policy with the key is attached to,
     * live, in the current scope, until when the latest such attachment lasts,
     * keyed by the role, in one query.
     *
     * @param  list<string>  $roles
     * @param  string  $policy
     * @return array<string, int>
     */
    private static function attachedToRoles(array $roles, string $policy): array
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Role> $class */
        $class = ModelClasses::get('role');

        $table = TableNames::get('authorizable_policies');
        $query = AuthorizationConnection::connection()->table($table)->useWritePdo()
            ->where($table . '.authorizable_type', (new $class)->getMorphClass())
            ->whereIn($table . '.authorizable_id', $roles)
            ->where($table . '.policy_id', $policy);

        TenantScope::currentChain()->grants($query, $table);
        GrantApplications::only($query, $table, TenantScope::currentApplication());

        $attached = [];

        foreach (LiveGrants::only($query, $table)->get([$table . '.authorizable_id as role_id', $table . '.expires_at as expires_at']) as $row) {
            /** @var array{role_id: string, expires_at: string|null} $read */
            $read  = (array) $row;
            $until = UtcDateTime::toUtc($read['expires_at'])?->getTimestamp() ?? \PHP_INT_MAX;

            $attached[$read['role_id']][] = $until;
        }

        return \array_map(static fn (array $untils): int => \max($untils), $attached);
    }

    /**
     * Read the live grants of the relation, with their expiry, on the write
     * connection.
     *
     * @param  \Illuminate\Database\Eloquent\Relations\MorphToMany<covariant \Illuminate\Database\Eloquent\Model, *, *>  $grants
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
     * @param  int|null  $time
     * @param  int|null  ...$times
     * @return int|null
     */
    private static function later(?int $time, ?int ...$times): ?int
    {
        return \max([$time, ...$times]);
    }
}
