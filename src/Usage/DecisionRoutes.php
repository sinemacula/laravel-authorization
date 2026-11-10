<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Usage;

use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableIdentity;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\AuthorizationLog;
use SineMacula\Laravel\Authorization\Support\SubjectGrants;

/**
 * The grant routes a decision rested on (N100), found from what the resolution
 * cache keeps beside the grants it weighed (see `ResolutionCache::routesOf()`),
 * in the scope the decision was made in, by the rules forward resolution
 * applied, so a check finds them with no query and nothing is recorded that the
 * decision did not weigh.
 *
 * - An allowed decision a permission held allowed rested on every live route
 *   behind that permission, redundant ones included, of the grantee whose
 *   permission matched (see `WeighedGrants`): the subject's own, or its
 *   granting identity's only when the subject's did not match, as
 *   `SubjectGrants::permissionFor()` reads them. That is the direct grant, each
 *   role grant that carried it, with the ancestor it reached.
 * - A decision one or more statements made, allow or deny, rested on each
 *   policy those statements belong to, by every route that attaches it to the
 *   subject, when the check read the subject's attachments through the
 *   package's policy resolver, or to its identity. An identity of the other
 *   kind gives the check its deny statements alone (see
 *   `SubjectGrants::identityPolicies()`), so its attachments count only for a
 *   decision its denies made. A policy that only denies counts too. A policy a
 *   policy store, a resource or a `withPolicies()` override supplied, a
 *   guardrail and a boundary are no grant, and use none.
 *
 * A grantee whose grants the package does not resolve, a custom
 * `getPermissions()` or policy resolver say, keeps no routes, so its decisions
 * use none. Finding the routes never throws into the check: a failure is
 * written to the log channel and no route is used.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class DecisionRoutes
{
    /**
     * Return the routes the decision about the subject rested on, of the grants
     * the check weighed, in the scope it was made in; none when they cannot be
     * found.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Decision  $decision
     * @param  \SineMacula\Laravel\Authorization\Usage\WeighedGrants  $weighed
     * @return list<\SineMacula\Laravel\Authorization\Usage\GrantRoute>
     */
    public static function of(Subject $subject, Decision $decision, WeighedGrants $weighed): array
    {
        return rescue(static function () use ($subject, $decision, $weighed): array {
            $cache = ResolutionCache::instance();

            return $cache === null ? [] : [...self::permissionsOf($cache, $decision, $weighed), ...self::policiesOf($cache, $subject, $decision, $weighed)];
        }, static function (\Throwable $exception): array {
            AuthorizationLog::warning('Authorization: the grants a check used could not be found — ' . $exception->getMessage(), [
                'reason' => $exception->getMessage(),
            ]);

            return [];
        }, false);
    }

    /**
     * Return the routes behind the permission held that allowed the decision,
     * of the grantee whose permission matched; none otherwise.
     *
     * @param  \SineMacula\Laravel\Authorization\Cache\ResolutionCache  $cache
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Decision  $decision
     * @param  \SineMacula\Laravel\Authorization\Usage\WeighedGrants  $weighed
     * @return list<\SineMacula\Laravel\Authorization\Usage\GrantRoute>
     */
    private static function permissionsOf(ResolutionCache $cache, Decision $decision, WeighedGrants $weighed): array
    {
        $last       = $decision->trace === [] ? null : $decision->trace[\array_key_last($decision->trace)];
        $permission = $decision->isAllowed() ? $last?->permission : null;
        $grantee    = $permission === null ? null : $weighed->granteeOf($permission);

        return $permission === null || $grantee === null ? [] : $cache->routesOf('permissions', $grantee)?->routesFor($permission) ?? [];
    }

    /**
     * Return the routes behind every policy one of the decision's statements
     * belongs to, attached to the subject or to its identity, as far as the
     * check weighed each.
     *
     * @param  \SineMacula\Laravel\Authorization\Cache\ResolutionCache  $cache
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Decision  $decision
     * @param  \SineMacula\Laravel\Authorization\Usage\WeighedGrants  $weighed
     * @return list<\SineMacula\Laravel\Authorization\Usage\GrantRoute>
     */
    private static function policiesOf(ResolutionCache $cache, Subject $subject, Decision $decision, WeighedGrants $weighed): array
    {
        $keys   = self::policyKeysOf($decision);
        $routes = [];

        foreach ($keys === [] ? [] : self::policyGranteesOf($subject, $decision, $weighed) as $grantee) {
            $attached = $cache->routesOf('policies', $grantee);

            foreach ($keys as $key) {
                \array_push($routes, ...$attached?->routesFor($key) ?? []);
            }
        }

        return $routes;
    }

    /**
     * Return the grantees whose attached policies the decision's statements may
     * belong to: the subject, when the check read its attachments through the
     * package's policy resolver, which reads an identity's alone, and its
     * identity when that is another model whose attachments the check read, one
     * of the other kind only for a decision its denies made.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Decision  $decision
     * @param  \SineMacula\Laravel\Authorization\Usage\WeighedGrants  $weighed
     * @return list<object>
     */
    private static function policyGranteesOf(Subject $subject, Decision $decision, WeighedGrants $weighed): array
    {
        $identity   = $subject->identity === $subject->subject ? null : $subject->identity;
        $isWeighed  = $identity !== null && $weighed->areIdentityPoliciesWeighed;
        $isIdentity = $isWeighed         && (SubjectGrants::grantingIdentity($subject) !== null || $decision->stage === DecisionStage::DENY);

        $isSubject = $weighed->areSubjectPoliciesWeighed && $subject->subject instanceof AuthorizableIdentity;

        return \array_values(\array_filter([$isSubject ? $subject->subject : null, $isIdentity ? $identity : null], \is_object(...)));
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
