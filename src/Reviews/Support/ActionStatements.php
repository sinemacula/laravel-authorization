<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Reviews\Support;

use SineMacula\Laravel\Authorization\Evaluation\AuthenticationRequirement;
use SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect;
use SineMacula\Laravel\Authorization\Evaluation\Policy;
use SineMacula\Laravel\Authorization\Evaluation\Statement;
use SineMacula\Laravel\Authorization\Reviews\ActionEvidence;
use SineMacula\Laravel\Authorization\Reviews\Enums\EvidenceKind;
use SineMacula\Laravel\Authorization\Reviews\OriginScope;

/**
 * Whether a policy held by a grant route names an action, as the policy matcher
 * reads its statements, and what those statements carry, for a review of
 * holdings filtered by the action.
 *
 * A statement names the action when its `actions` cover it, or its
 * `not_actions` leave it out (see `Statement::coversAction()`), the action
 * always literal. An allow statement that names `principals` applies only in a
 * policy attached to a resource, never in one attached to a grantee or a role
 * (see `PolicyEvaluator::isForSubject()`), so it gives the holder nothing and
 * is passed over; a deny takes no principals. Nothing else is evaluated: the
 * conditions, resource patterns and authentication requirements of the
 * statements naming the action are reported as present, never decided.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ActionStatements
{
    /**
     * Return what the policy's statements naming the action give, reaching as
     * given: allow when one allows it, else deny; null when none names it.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Policy  $policy
     * @param  string  $action
     * @param  \SineMacula\Laravel\Authorization\Reviews\OriginScope  $reach
     * @return \SineMacula\Laravel\Authorization\Reviews\ActionEvidence|null
     */
    public static function evidence(Policy $policy, string $action, OriginScope $reach): ?ActionEvidence
    {
        $naming = \array_filter($policy->statements, static fn (Statement $statement): bool => self::names($statement, $action));

        if ($naming === []) {
            return null;
        }

        $effects  = \array_map(static fn (Statement $statement): PolicyEffect => $statement->effect, $naming);
        $operator = AuthenticationRequirement::OPERATOR;

        return new ActionEvidence(
            $action,
            EvidenceKind::POLICY_STATEMENT,
            \in_array(PolicyEffect::ALLOW, $effects, true) ? PolicyEffect::ALLOW : PolicyEffect::DENY,
            $reach,
            hasDeny: \in_array(PolicyEffect::DENY, $effects, true),
            hasConditions: self::isAnyOf($naming, static fn (Statement $statement): bool => \array_diff(\array_keys($statement->conditions), [$operator]) !== []),
            hasResourcePatterns: self::isAnyOf($naming, static fn (Statement $statement): bool => $statement->resources !== null || $statement->notResources !== null),
            hasRequirements: self::isAnyOf($naming, static fn (Statement $statement): bool => \array_key_exists($operator, $statement->conditions)),
        );
    }

    /**
     * Determine whether the statement names the action for a holder of its
     * policy: it covers the action, and it is a deny, or an allow naming no
     * principals.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Statement  $statement
     * @param  string  $action
     * @return bool
     */
    private static function names(Statement $statement, string $action): bool
    {
        return $statement->coversAction($action) && ($statement->effect === PolicyEffect::DENY || $statement->principals === null);
    }

    /**
     * Determine whether any of the statements carries what the test asks.
     *
     * @param  array<array-key, \SineMacula\Laravel\Authorization\Evaluation\Statement>  $statements
     * @param  \Closure(\SineMacula\Laravel\Authorization\Evaluation\Statement): bool  $test
     * @return bool
     */
    private static function isAnyOf(array $statements, \Closure $test): bool
    {
        return \array_filter($statements, $test) !== [];
    }
}
