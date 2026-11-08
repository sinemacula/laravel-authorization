<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Administration;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Query\Builder as QueryBuilder;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Enums\DependencyPhase;
use SineMacula\Laravel\Authorization\Evaluation\CheckSources;
use SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect;
use SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException;
use SineMacula\Laravel\Authorization\Evaluation\Policy;
use SineMacula\Laravel\Authorization\Evaluation\SessionCaps;
use SineMacula\Laravel\Authorization\Evaluation\Statement;
use SineMacula\Laravel\Authorization\Models\Policy as StoredPolicy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\OperationScope;
use SineMacula\Laravel\Authorization\Support\PolicyDocument;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\RoleGraph;

/**
 * Whether anything that caps or denies a subject could limit a permission
 * anywhere a delegated grant of it would reach, for the possession route of the
 * grant (N77), and for the administration action itself across a reach wider
 * than the node it is decided at (see `AdministeredScope`). The route proves
 * the grant contained, and the actor administers the reach, only when nothing
 * could: when in doubt, the permission is limited.
 *
 * What is read:
 *
 * - every source the check of the permission reads in the grant's scope: the
 *   policies, the boundaries, the guardrails and the session caps, a custom
 *   policy resolver's included;
 * - as stored, on the write connection, outside every tenant scope, whatever
 *   their application and expiry, each held, attached or set in a tenant of the
 *   grant's reach (see `GrantReach`): the policies attached to the subject's
 *   principal and identity, and to every role either holds and the roles above
 *   them, the policies attached to any resource, the boundaries of the
 *   principal and the identity, and the guardrails.
 *
 * Each table is read in one query, the reach and the grantees in it, and every
 * policy found is read in one more, so what is read grows with what applies in
 * the reach, never with the policies, boundaries or guardrails of other
 * tenants. A tree, a row or a document that cannot be read limits the
 * permission, and so do more resource-policy attachments, or more guardrails,
 * in the reach than `authorization.administration.max_impact` allows. Inside a
 * delegated operation, those attachments and guardrails, and the policies read,
 * are locked and pinned (see `DependencyPins`), so a deny attached meanwhile
 * has the operation tried again rather than written past it.
 *
 * The permission is limited when any deny statement among them names an action
 * the permission covers, with conditions, resource patterns or none; when a
 * boundary or a guardrail has no allow statement naming every action the
 * permission covers, with no condition and on every resource; and when a
 * session cap does not cover every action it covers. Patterns are compared as
 * `fnmatch()` compares names: a deny of `posts:edit` limits a grant of
 * `posts:*`, and a cap of `posts:*` covers a grant of `posts:edit`. Two
 * patterns that both hold wildcards, one of them `?` or a `[...]` class, are
 * taken to overlap, and a pattern holding `?` or a class never covers a grant
 * of a wildcard, since whether they would cannot be told simply.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class PossessionLimits
{
    /**
     * Determine whether anything that applies to the subject anywhere in the
     * grant's reach could limit the permission.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  string  $permission
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $scope
     * @param  \SineMacula\Laravel\Authorization\Evaluation\CheckSources  $sources
     * @return bool
     */
    public static function isLimited(Subject $subject, string $permission, GrantScope $scope, CheckSources $sources): bool
    {
        return self::limitedEach($subject, $scope, [$permission => $sources])[$permission];
    }

    /**
     * Determine, for each of the permissions, whether anything that applies to
     * the subject anywhere in the grant's reach could limit it, keyed by the
     * permission, reading what is stored in the reach once for them all, so the
     * cost never grows with the permissions.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $scope
     * @param  array<array-key, \SineMacula\Laravel\Authorization\Evaluation\CheckSources>  $sources
     * @return array<array-key, bool>
     */
    public static function limitedEach(Subject $subject, GrantScope $scope, array $sources): array
    {
        if ($sources === []) {
            return [];
        }

        try {
            [$denying, $capping] = self::stored($subject, GrantReach::of($scope));
        } catch (\Throwable) {
            return \array_map(static fn (): bool => true, $sources);
        }

        $limited = [];

        foreach ($sources as $permission => $checked) {
            $caps = [...$capping, ...$checked->boundaries, ...$checked->guardrails ?? []];
            $name = (string) $permission;

            $limited[$permission] = self::denies([...$checked->policies, ...$denying, ...$caps], $name)
                || !self::isCoveredByEvery($caps, $name)
                || !self::isCoveredByCaps($checked->session, $name);
        }

        return $limited;
    }

    /**
     * Determine whether two action patterns name an action in common. A pattern
     * with no wildcard names itself alone, so it overlaps another it matches;
     * two whose only wildcard is `*` overlap when the text before the first `*`
     * of one starts the other's, and the text after the last `*` of one ends
     * the other's; any other two, one holding `?` or a `[...]` class, are taken
     * to overlap.
     *
     * @param  string  $pattern
     * @param  string  $other
     * @return bool
     */
    public static function isOverlapping(string $pattern, string $other): bool
    {
        if (!self::isWildcard($pattern) || !self::isWildcard($other)) {
            return \fnmatch($pattern, $other, \FNM_NOESCAPE) || \fnmatch($other, $pattern, \FNM_NOESCAPE);
        }

        if (self::hasClass($pattern) || self::hasClass($other)) {
            return true;
        }

        [$head, $tail]           = self::ends($pattern);
        [$otherHead, $otherTail] = self::ends($other);

        return (\str_starts_with($head, $otherHead) || \str_starts_with($otherHead, $head)) && (\str_ends_with($tail, $otherTail) || \str_ends_with($otherTail, $tail));
    }

    /**
     * Return the policies stored for the subject in the reach that may deny
     * (its policies, its roles' and every resource's), and those that cap (its
     * boundaries and the guardrails), hydrated.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  \SineMacula\Laravel\Authorization\Administration\GrantReach  $reach
     * @return array{list<\SineMacula\Laravel\Authorization\Evaluation\Policy>, list<\SineMacula\Laravel\Authorization\Evaluation\Policy>}
     *
     * @throws \SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException
     */
    private static function stored(Subject $subject, GrantReach $reach): array
    {
        $grantees = [];

        foreach ([$subject->subject, $subject->identity] as $side) {
            if (!$side instanceof Model) {
                continue;
            }

            $grantees[] = Reference::of($side);
        }

        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Role> $role */
        $role  = config('authorization.models.role', Role::class);
        $roles = \array_keys(RoleGraph::reach(self::keys('authorizable_roles', 'role_id', $grantees, $reach)));
        $held  = [...$grantees, ...\array_map(static fn (string $key): Reference => new Reference((new $role)->getMorphClass(), $key), $roles)];

        $denying  = [...self::keys('authorizable_policies', 'policy_id', $held, $reach), ...self::keys('resource_policies', 'policy_id', null, $reach)];
        $capping  = [...self::keys('authorizable_boundaries', 'policy_id', $grantees, $reach), ...self::keys('guardrails', 'policy_id', null, $reach)];
        $policies = self::hydrated([...$denying, ...$capping]);

        return [self::pick($policies, $denying), self::pick($policies, $capping)];
    }

    /**
     * Return the distinct keys in the column of the rows of the table held in a
     * tenant of the reach, or platform-wide: the rows the grantees hold, or
     * every row for no grantees, in one query. Every row for no grantees, the
     * resource policies and the guardrails of the reach, is read only when
     * there are no more than `authorization.administration.max_impact`, and
     * inside a delegated operation locked and pinned (see
     * `DependencyPins::keysWithin()`), so one added meanwhile is noticed before
     * the write; more throws, so the permission is limited.
     *
     * @param  string  $table
     * @param  string  $column
     * @param  list<\SineMacula\Laravel\Authorization\Support\Reference>|null  $grantees
     * @param  \SineMacula\Laravel\Authorization\Administration\GrantReach  $reach
     * @return list<string>
     *
     * @throws \OverflowException
     * @throws \LogicException
     */
    private static function keys(string $table, string $column, ?array $grantees, GrantReach $reach): array
    {
        if ($grantees === []) {
            return [];
        }

        /** @var string $name */
        $name  = config('authorization.tables.' . $table, $table);
        $query = $reach->constrain(AuthorizationConnection::connection()->table($name)->useWritePdo(), $name);

        if ($grantees === null) {
            $keys = DependencyPins::keysWithin($query, $column, AffectedHolders::limit());

            return $keys ?? throw new \OverflowException("More rows of [{$name}] in the reach than the impact limit allows.");
        }

        $query->where(static function (QueryBuilder $query) use ($grantees, $name): void {
            foreach ($grantees as $grantee) {
                $query->orWhere(static fn (QueryBuilder $row): QueryBuilder => $row
                    ->where($name . '.authorizable_type', $grantee->type)
                    ->where($name . '.authorizable_id', $grantee->id));
            }
        });

        /** @var list<string> */
        return $query->distinct()->pluck($name . '.' . $column)->all();
    }

    /**
     * Return the stored policies with the keys, hydrated, keyed by their keys,
     * read in one query; one that is gone, or whose document cannot be read,
     * throws.
     *
     * @param  list<string>  $keys
     * @return array<string, \SineMacula\Laravel\Authorization\Evaluation\Policy>
     *
     * @throws \SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException
     */
    private static function hydrated(array $keys): array
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Policy> $class */
        $class    = config('authorization.models.policy', StoredPolicy::class);
        $model    = new $class;
        $policies = [];

        /** @var string $table */
        $table = config('authorization.tables.policies', 'policies');

        $sorted = \array_unique($keys);

        \sort($sorted, \SORT_STRING);

        OperationScope::pins()?->lock(DependencyPhase::HOLDERS, AuthorizationConnection::connection()->table($table)->whereIn('id', $sorted));

        foreach ($class::query()->withoutGlobalScopes()->useWritePdo()->whereKey($keys)->get([$model->getKeyName(), 'name', 'owner_type', 'owner_id', 'document']) as $stored) {
            /** @var int|string $key */
            $key = $stored->getKey();

            $policies['policy:' . $key] = PolicyDocument::hydrate($stored);
        }

        return $policies;
    }

    /**
     * Return the hydrated policies with the keys, in their order; a key with no
     * policy throws, as a policy that is gone limits.
     *
     * @param  array<string, \SineMacula\Laravel\Authorization\Evaluation\Policy>  $policies
     * @param  list<string>  $keys
     * @return list<\SineMacula\Laravel\Authorization\Evaluation\Policy>
     *
     * @throws \SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException
     */
    private static function pick(array $policies, array $keys): array
    {
        return \array_map(static fn (string $key): Policy => $policies['policy:' . $key] ?? throw new InvalidPolicyDocumentException($key, 'the policy is gone'), $keys);
    }

    /**
     * Determine whether a deny statement of any of the policies names an action
     * the permission covers.
     *
     * @param  array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>  $policies
     * @param  string  $permission
     * @return bool
     */
    private static function denies(array $policies, string $permission): bool
    {
        foreach ($policies as $policy) {
            foreach ($policy->statements as $statement) {
                if ($statement->effect === PolicyEffect::DENY && self::names($statement, $permission)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Determine whether the statement names any action the permission covers:
     * one of its `actions` overlaps it, or none of its `not_actions` covers it
     * whole.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Statement  $statement
     * @param  string  $permission
     * @return bool
     */
    private static function names(Statement $statement, string $permission): bool
    {
        return $statement->notActions === null ? self::hasOverlapping($statement->actions ?? [], $permission) : !self::isCoveredByAny($statement->notActions, $permission);
    }

    /**
     * Determine whether every one of the policies, each a boundary or a
     * guardrail, allows every action the permission covers, with no condition,
     * on every resource.
     *
     * @param  array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>  $policies
     * @param  string  $permission
     * @return bool
     */
    private static function isCoveredByEvery(array $policies, string $permission): bool
    {
        foreach ($policies as $policy) {
            if (!self::allowsWhole($policy, $permission)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Determine whether the policy has an allow statement naming every action
     * the permission covers, with no condition, on every resource.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Policy  $policy
     * @param  string  $permission
     * @return bool
     */
    private static function allowsWhole(Policy $policy, string $permission): bool
    {
        foreach ($policy->statements as $statement) {
            if (self::isUnconditionalAllow($statement) && self::namesWhole($statement, $permission)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Determine whether the statement is an allow with no condition and no
     * principals, on every resource.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Statement  $statement
     * @return bool
     */
    private static function isUnconditionalAllow(Statement $statement): bool
    {
        $everywhere = $statement->notResources === null && ($statement->resources === null || \in_array('*', $statement->resources, true));
        $plain      = $statement->conditions   === []   && $statement->principals === null;

        return $statement->effect === PolicyEffect::ALLOW && $plain && $everywhere;
    }

    /**
     * Determine whether the statement names every action the permission covers:
     * one of its `actions` covers it whole, or none of its `not_actions` names
     * any of them.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Statement  $statement
     * @param  string  $permission
     * @return bool
     */
    private static function namesWhole(Statement $statement, string $permission): bool
    {
        return $statement->notActions === null
            ? self::isCoveredByAny($statement->actions ?? [], $permission)
            : !self::hasOverlapping($statement->notActions, $permission);
    }

    /**
     * Determine whether every session cap covers every action the permission
     * covers.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\SessionCaps  $session
     * @param  string  $permission
     * @return bool
     */
    private static function isCoveredByCaps(SessionCaps $session, string $permission): bool
    {
        foreach ($session->caps as [, $patterns]) {
            if (!self::isCoveredByAny($patterns, $permission)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Determine whether one of the patterns covers every action the permission
     * covers: it matches the permission's name taken literally. A pattern
     * holding `?` or a `[...]` class could match a `*` of the name as one
     * character, so it covers a name without a wildcard alone.
     *
     * @param  list<string>  $patterns
     * @param  string  $permission
     * @return bool
     */
    private static function isCoveredByAny(array $patterns, string $permission): bool
    {
        foreach ($patterns as $pattern) {
            $isSound = !self::hasClass($pattern) || !self::isWildcard($permission);

            if ($isSound && SessionCaps::covers([$pattern], $permission)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Determine whether one of the patterns names an action the permission
     * covers.
     *
     * @param  list<string>  $patterns
     * @param  string  $permission
     * @return bool
     */
    private static function hasOverlapping(array $patterns, string $permission): bool
    {
        foreach ($patterns as $pattern) {
            if (self::isOverlapping($pattern, $permission)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Return the text before the first `*` of a pattern and after its last.
     *
     * @param  string  $pattern
     * @return array{string, string}
     */
    private static function ends(string $pattern): array
    {
        return [\substr($pattern, 0, (int) \strpos($pattern, '*')), \substr($pattern, (int) \strrpos($pattern, '*') + 1)];
    }

    /**
     * Determine whether the pattern holds a wildcard: `*`, `?` or a `[...]`
     * class.
     *
     * @param  string  $pattern
     * @return bool
     */
    private static function isWildcard(string $pattern): bool
    {
        return \strpbrk($pattern, '*?[') !== false;
    }

    /**
     * Determine whether the pattern holds a wildcard of one character: `?` or a
     * `[...]` class.
     *
     * @param  string  $pattern
     * @return bool
     */
    private static function hasClass(string $pattern): bool
    {
        return \strpbrk($pattern, '?[') !== false;
    }
}
