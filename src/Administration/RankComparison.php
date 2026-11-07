<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Administration;

use SineMacula\Laravel\Authorization\Contracts\SupportsRoles;
use SineMacula\Laravel\Authorization\Support\AuthorizationScope;

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
 * Then:
 *
 * - seniority is strict: the actor acts on the target only when its rank is
 *   smaller, so an equal rank refuses;
 * - a target holding no ranked role counts as the most junior;
 * - an actor holding no ranked role is the most junior too, so it acts on no
 *   one, a target holding no ranked role included, since equal rank refuses;
 * - an actor or target whose roles cannot be read (it does not support them)
 *   cannot be compared, so the comparison fails closed, as
 *   `administration.rank_uncomparable` reports it;
 * - with `authorization.rank.enabled` false, rank is no constraint, and every
 *   comparison passes, which still grants nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class RankComparison
{
    /**
     * Determine whether rank lets the actor act on the target, in the scope, or
     * the current one when none is given.
     *
     * @param  object  $actor
     * @param  object  $target
     * @param  \SineMacula\Laravel\Authorization\Support\AuthorizationScope|null  $scope
     * @return bool
     */
    public static function canActOn(object $actor, object $target, ?AuthorizationScope $scope = null): bool
    {
        /** @var bool $isEnabled */
        $isEnabled = config('authorization.rank.enabled', true);

        if (!$isEnabled) {
            return true;
        }

        if (!self::isComparable($actor) || !self::isComparable($target)) {
            return false;
        }

        $compare = static function () use ($actor, $target): bool {
            $actorRank = self::rankOf($actor);

            return $actorRank !== null && $actorRank < (self::rankOf($target) ?? \PHP_INT_MAX);
        };

        return $scope === null ? $compare() : $scope->within($compare);
    }

    /**
     * Determine whether the holder's rank can be read: it holds roles through
     * the package's role relation.
     *
     * @param  object  $holder
     * @return bool
     */
    public static function isComparable(object $holder): bool
    {
        return $holder instanceof SupportsRoles && \method_exists($holder, 'roles');
    }

    /**
     * Return the most senior rank among the roles the holder holds in the
     * current scope, or null when it holds no ranked role, or its roles cannot
     * be read.
     *
     * @param  object  $holder
     * @return int|null
     */
    public static function rankOf(object $holder): ?int
    {
        if (!$holder instanceof SupportsRoles || !\method_exists($holder, 'roles')) {
            return null;
        }

        $ranks = [];

        /** @var iterable<int, \SineMacula\Laravel\Authorization\Models\Role> $roles */
        $roles = $holder->roles()->get();

        foreach ($roles as $role) {
            if ($role->rank === null) {
                continue;
            }

            $ranks[] = $role->rank;
        }

        return $ranks === [] ? null : \min($ranks);
    }
}
