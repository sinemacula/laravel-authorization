<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Usage;

use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Contracts\SupportsPermissions;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\SubjectGrants;

/**
 * The grant routes a decision used (N100), found from what the resolution cache
 * keeps beside the subject's grants (see `ResolutionCache::routesOf()`), in the
 * scope the decision was made in, so a warm check finds them with no query.
 *
 * - An allowed decision a permission held allowed used every live route behind
 *   a permission that covers the action, the subject's and its identity's when
 *   the identity grants to it, redundant ones included: the direct grant, each
 *   role grant that carried it, with the ancestor it reached, and the
 *   identity's grant. The identity's permissions are resolved for it when the
 *   check did not need them, through the cache, so a warm check reads none.
 * - A decision one or more statements made, allow or deny, used each policy
 *   those statements belong to, by every route that attaches it to the subject
 *   or its identity, a policy that only denies included. A policy a policy
 *   store, a resource or a `withPolicies()` override supplied, a guardrail and
 *   a boundary are no grant, and use none.
 *
 * A grantee whose grants the package does not resolve, a custom
 * `getPermissions()` or policy resolver say, keeps no routes, so its decisions
 * use none.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class DecisionRoutes
{
    /**
     * Return the routes the decision about the subject on the action used, in
     * the scope it was made in; none when the policies were overridden, for
     * those of its statements.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  string  $action
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Decision  $decision
     * @param  bool  $isOverridden
     * @return list<\SineMacula\Laravel\Authorization\Usage\GrantRoute>
     */
    public static function of(Subject $subject, string $action, Decision $decision, bool $isOverridden): array
    {
        $cache = ResolutionCache::instance();

        if ($cache === null) {
            return [];
        }

        $policies = $isOverridden ? [] : self::policiesOf($cache, $subject, $decision);

        return [...self::permissionsOf($cache, $subject, $action, $decision), ...$policies];
    }

    /**
     * Return the routes behind every permission held that covers the action,
     * when a permission held allowed the decision; none otherwise.
     *
     * @param  \SineMacula\Laravel\Authorization\Cache\ResolutionCache  $cache
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  string  $action
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Decision  $decision
     * @return list<\SineMacula\Laravel\Authorization\Usage\GrantRoute>
     */
    private static function permissionsOf(ResolutionCache $cache, Subject $subject, string $action, Decision $decision): array
    {
        $last = $decision->trace === [] ? null : $decision->trace[\array_key_last($decision->trace)];

        if (!$decision->isAllowed() || $last?->permission === null) {
            return [];
        }

        $routes = [];

        foreach ([$subject->subject, SubjectGrants::grantingIdentity($subject)] as $grantee) {
            foreach (self::permissionRoutesOf($cache, $grantee) as $name => $list) {
                if ($name !== $action && !\fnmatch($name, $action, \FNM_NOESCAPE)) {
                    continue;
                }

                \array_push($routes, ...$list);
            }
        }

        return $routes;
    }

    /**
     * Return the routes behind each permission the grantee holds, resolving its
     * permissions through the cache when it has not been yet; none for a
     * grantee that holds no permissions, or whose resolution cannot say.
     *
     * @param  \SineMacula\Laravel\Authorization\Cache\ResolutionCache  $cache
     * @param  object|null  $grantee
     * @return array<string, list<\SineMacula\Laravel\Authorization\Usage\GrantRoute>>
     */
    private static function permissionRoutesOf(ResolutionCache $cache, ?object $grantee): array
    {
        if (!$grantee instanceof SupportsPermissions) {
            return [];
        }

        $routes = $cache->routesOf('permissions', $grantee);

        if ($routes === null) {
            $grantee->getPermissions();
        }

        return $routes ?? $cache->routesOf('permissions', $grantee) ?? [];
    }

    /**
     * Return the routes behind every policy one of the decision's statements
     * belongs to, attached to the subject or to its identity.
     *
     * @param  \SineMacula\Laravel\Authorization\Cache\ResolutionCache  $cache
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Decision  $decision
     * @return list<\SineMacula\Laravel\Authorization\Usage\GrantRoute>
     */
    private static function policiesOf(ResolutionCache $cache, Subject $subject, Decision $decision): array
    {
        $keys = self::policyKeysOf($decision);

        if ($keys === []) {
            return [];
        }

        $routes = [];

        foreach ($subject->identity === $subject->subject ? [$subject->subject] : [$subject->subject, $subject->identity] as $grantee) {
            $attached = \is_object($grantee) ? $cache->routesOf('policies', $grantee) ?? [] : [];

            foreach ($keys as $key) {
                \array_push($routes, ...$attached[$key] ?? []);
            }
        }

        return $routes;
    }

    /**
     * Return the key of each stored policy one of the decision's statements
     * belongs to, each once, when the statements decided at the deny or the
     * allow stage; a resource policy's statement, and a policy built in code,
     * name none.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Decision  $decision
     * @return array<string, string>
     */
    private static function policyKeysOf(Decision $decision): array
    {
        $isPolicyStage = $decision->stage === DecisionStage::DENY || $decision->stage === DecisionStage::ALLOW;
        $keys          = [];

        foreach ($isPolicyStage ? $decision->statements : [] as $statement) {
            if ($statement->resource !== null || $statement->policyId === null) {
                continue;
            }

            $keys[$statement->policyId] = $statement->policyId;
        }

        return $keys;
    }
}
