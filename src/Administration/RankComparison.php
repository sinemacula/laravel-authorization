<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Administration;

use Illuminate\Contracts\Database\Query\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use SineMacula\Laravel\Authorization\Contracts\SupportsRoles;
use SineMacula\Laravel\Authorization\Database\GrantApplications;
use SineMacula\Laravel\Authorization\Database\LiveGrants;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\AuthorizationScope;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\SubjectGrants;

/**
 * The one comparison of rank delegated administration makes (AUTHZ-3.5, N76):
 * whether an actor's rank lets it act on a target. It grants nothing by itself:
 * it is one constraint among the others, never an allow, so passing it says
 * only that rank does not stand in the way.
 *
 * Both sides are resolved through the same path, scope-aware: the roles each
 * holds in the scope, the current tenant and application unless one is given, a
 * grant that has expired, or holds in another tenant or application, never
 * counting; each side's rank is the most senior (the smallest) rank among them.
 * An actor given as a resolved `Subject` holds the roles that reach it in a
 * check: its principal's, and its identity's when the identity grants to it
 * (see `SubjectGrants::grantingIdentity()`). Then:
 *
 * - seniority is strict: the actor acts on the target only when its rank is
 *   smaller, so an equal rank refuses;
 * - a target holding no ranked role counts as the most junior;
 * - an actor holding no ranked role is the most junior too, so it acts on no
 *   one, a target holding no ranked role included, since equal rank refuses;
 * - the rank of a role the change would grant the target counts as the target's
 *   too, so a grant never leaves the target equal to or senior to the actor;
 * - an actor or target whose roles cannot be read (it does not support them)
 *   cannot be compared, so the comparison fails closed, as
 *   `administration.rank_uncomparable` reports it;
 * - with `authorization.rank.enabled` false, rank is no constraint, and every
 *   comparison passes, which still grants nothing.
 *
 * Roles are read on the write connection, as every other source of a decision
 * is, so a screen and the service compare the same rows. A delegated change
 * reads the target's rank across the whole reach of the change instead (see
 * `rankAcross()`): the most senior rank the target holds anywhere the change
 * reaches counts.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class RankComparison
{
    /**
     * Determine whether rank lets the actor act on the target, in the scope, or
     * the current one when none is given, once the target also holds a role of
     * the rank granted, when one is given.
     *
     * @param  object  $actor
     * @param  object  $target
     * @param  \SineMacula\Laravel\Authorization\Support\AuthorizationScope|null  $scope
     * @param  int|null  $granted
     * @return bool
     */
    public static function canActOn(object $actor, object $target, ?AuthorizationScope $scope = null, ?int $granted = null): bool
    {
        if (!self::isEnabled()) {
            return true;
        }

        if (!self::isComparable($actor) || !self::isComparable($target)) {
            return false;
        }

        $compare = static function () use ($actor, $target, $granted): bool {
            $actorRank = self::rankOf($actor);

            return $actorRank !== null && $actorRank < \min(self::rankOf($target) ?? \PHP_INT_MAX, $granted ?? \PHP_INT_MAX);
        };

        return $scope === null ? $compare() : $scope->within($compare);
    }

    /**
     * Determine whether rank is a constraint: `authorization.rank.enabled`.
     *
     * @return bool
     */
    public static function isEnabled(): bool
    {
        /** @var bool */
        return config('authorization.rank.enabled', true);
    }

    /**
     * Determine whether the holder's rank can be read: it holds roles through
     * the package's role relation, or, for a resolved subject, its principal or
     * the identity granting to it does.
     *
     * @param  object  $holder
     * @return bool
     */
    public static function isComparable(object $holder): bool
    {
        foreach (self::holders($holder) as $side) {
            if ($side instanceof SupportsRoles && \method_exists($side, 'roles')) {
                return true;
            }
        }

        return false;
    }

    /**
     * Return the most senior rank among the roles the holder holds in the
     * current scope, or null when it holds no ranked role, or its roles cannot
     * be read; for a resolved subject, among its principal's and its granting
     * identity's.
     *
     * @param  object  $holder
     * @return int|null
     */
    public static function rankOf(object $holder): ?int
    {
        $ranks = [];

        foreach (self::holders($holder) as $side) {
            if (!$side instanceof SupportsRoles || !\method_exists($side, 'roles')) {
                continue;
            }

            /** @var iterable<int, \SineMacula\Laravel\Authorization\Models\Role> $roles */
            $roles = $side->roles()->useWritePdo()->get(); // @phpstan-ignore method.notFound

            foreach ($roles as $role) {
                $ranks[] = $role->rank;
            }
        }

        $ranks = \array_filter($ranks, static fn (?int $rank): bool => $rank !== null);

        return $ranks === [] ? null : \min($ranks);
    }

    /**
     * Return the most senior rank among the roles the target holds live
     * anywhere the grant scope reaches, or null when it holds no ranked role
     * there, in one query on the write connection: its grants of every
     * application for a grant to every application, else of that application
     * and of every application; held platform-wide, or in a tenant of the reach
     * (see `GrantReach`), every tenant for a platform-wide grant.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $target
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $scope
     * @return int|null
     *
     * @throws \UnexpectedValueException
     */
    public static function rankAcross(Model $target, GrantScope $scope): ?int
    {
        return self::rankAcrossAll([Reference::of($target)], $scope);
    }

    /**
     * Return the most senior rank among the roles any of the holders holds live
     * anywhere the grant scope reaches, as `rankAcross()` reads it for one, or
     * null when none holds a ranked role there, in one query on the write
     * connection, however many holders there are, so the impact of a change on
     * every holder of a definition is read at a fixed cost (see `Impact`).
     *
     * @param  list<\SineMacula\Laravel\Authorization\Support\Reference>  $holders
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $scope
     * @return int|null
     *
     * @throws \UnexpectedValueException
     */
    public static function rankAcrossAll(array $holders, GrantScope $scope): ?int
    {
        if ($holders === []) {
            return null;
        }

        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Role> $class */
        $class = config('authorization.models.role', Role::class);

        /** @var string $pivot */
        $pivot = config('authorization.tables.authorizable_roles', 'authorizable_roles');
        $role  = new $class;
        $query = $class::query()->withoutGlobalScopes()->useWritePdo()->join($pivot, $pivot . '.role_id', '=', $role->getQualifiedKeyName())
            ->where(static function (Builder $query) use ($pivot, $holders): void {
                foreach (self::byType($holders) as $type => $ids) {
                    $query->orWhere(static fn (Builder $held): Builder => $held->where($pivot . '.authorizable_type', $type)->whereIn($pivot . '.authorizable_id', $ids));
                }
            });

        if ($scope->application !== null) {
            GrantApplications::only($query, $pivot, $scope->application);
        }

        $rank  = $role->qualifyColumn('rank');
        $ranks = [];

        foreach (GrantReach::of($scope)->constrain(LiveGrants::only($query, $pivot), $pivot)->whereNotNull($rank)->get([$rank]) as $held) {
            $ranks[] = $held->rank;
        }

        return $ranks === [] ? null : \min($ranks);
    }

    /**
     * Return the actor's rank in the tenant, or at platform scope for none, and
     * the application, as the grant's own scope ranks it, or null when it holds
     * no ranked role there.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $actor
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  string|null  $application
     * @return int|null
     */
    public static function rankIn(Subject $actor, ?Reference $tenant, ?string $application): ?int
    {
        $scope = $tenant === null ? AuthorizationScope::platform($application) : AuthorizationScope::tenant($tenant, $application);

        return $scope->within(static fn (): ?int => self::rankOf($actor));
    }

    /**
     * Determine whether a holder of the morph type can be ranked: the type
     * names a model whose roles can be read (see `isComparable()`).
     *
     * @param  string  $type
     * @return bool
     */
    public static function isComparableType(string $type): bool
    {
        $class = Relation::getMorphedModel($type) ?? $type;

        return \class_exists($class) && \is_subclass_of($class, Model::class) && self::isComparable(new $class);
    }

    /**
     * Return the keys of the holders, grouped by morph type.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Support\Reference>  $holders
     * @return array<string, list<string>>
     */
    private static function byType(array $holders): array
    {
        $grouped = [];

        foreach ($holders as $holder) {
            $grouped[$holder->type][] = $holder->id;
        }

        return $grouped;
    }

    /**
     * Return the models whose roles make the holder's rank: a resolved
     * subject's principal and the identity granting to it, or the holder
     * itself.
     *
     * @param  object  $holder
     * @return list<object>
     */
    private static function holders(object $holder): array
    {
        if (!$holder instanceof Subject) {
            return [$holder];
        }

        $identity = SubjectGrants::grantingIdentity($holder);

        return $identity === null ? [$holder->subject] : [$holder->subject, $identity];
    }
}
