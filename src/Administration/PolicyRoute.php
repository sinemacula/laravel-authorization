<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Administration;

use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Evaluation\Statement;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Support\DocumentDigest;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;

/**
 * Whether handing out a policy hands out only what the actor may hand out
 * (N77): a policy attached to a principal, an identity or a role, each policy a
 * granted role or a new parent carries, a policy rewritten for its holders, and
 * a policy attached to a resource, each across the change's whole reach and
 * lifetime, by one of two routes.
 *
 * 1. **Containment.** Every allow statement handed out names its actions alone,
 *    with `actions`, never `not_actions`, no resource patterns and no
 *    conditions, and each action passes the permission route (see
 *    `Possession`): held across the reach and lifetime, or explicitly
 *    grantable. A policy attached to a resource also names its principals,
 *    whose authority the impact check weighs (see `Impact`), so they never
 *    stand in the way there, nor where its allows that select a granted role
 *    are handed to the grantee (see `RoleAuthority`); anywhere else a statement
 *    naming principals cannot be proved contained.
 * 2. **Explicit grantability.** `authorization:policy.grantable` is allowed, in
 *    the change's reach and for its lifetime, on the descriptor naming the
 *    policy and the digest of the document handed out (see
 *    `OperationResource::policyGrantable()`), so a right a policy allows for
 *    one document, by a condition on `resource.digest`, never covers the policy
 *    rewritten.
 *
 * A deny statement hands nothing out, and never justifies an allow. A policy
 * that allows nothing passes. Every action of a policy is decided in one pass
 * (see `Possession::refusalOfEach()`). The policy is the one its caller hands
 * in, which a service reads as stored first, so its document and digest are the
 * row's. When neither route holds, the refusal is the permission route's, for a
 * policy that could be contained, and `administration.unprovable` otherwise, a
 * document that cannot be read included.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class PolicyRoute
{
    /**
     * Return why handing out the stored policy across the change is refused, or
     * null when it is allowed.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $operation
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationChange  $change
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null
     */
    public static function refusal(OperationResource $operation, OperationChange $change, Policy $policy, FurtherChecks $checks): ?DecisionReason
    {
        return self::refusalOf($operation, $change, $policy, $policy->document, self::allowsOf(DocumentComparison::read($policy->document)), $checks);
    }

    /**
     * Return why handing out the allows of the document, the policy's new
     * document or one it is attached to resources by, is refused, or null when
     * it is allowed; null allows stand for a document that cannot be read.
     * Allows that reach the grantee by naming it, or a role it is given, as a
     * principal, as those of a resource policy do, are selected: their
     * principals never stand in the way of containment.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $operation
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationChange  $change
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @param  mixed  $document
     * @param  list<\SineMacula\Laravel\Authorization\Evaluation\Statement>|null  $allows
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @param  bool  $isSelected
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null
     */
    public static function refusalOf(
        OperationResource $operation,
        OperationChange $change,
        Policy $policy,
        mixed $document,
        ?array $allows,
        FurtherChecks $checks,
        bool $isSelected = false,
    ): ?DecisionReason {
        if ($allows === []) {
            return null;
        }

        $principals = $isSelected || $operation->action === PackagePermissions::RESOURCE_POLICY_ATTACH;

        $refusal = $allows === null ? DecisionReason::ADMINISTRATION_UNPROVABLE : self::uncontained($operation, $change, $allows, $principals, $checks);
        $digest  = self::digestOf($document);

        return $refusal === null || ($digest !== null && Possession::isGrantable($operation, $change, $operation->policyGrantable($policy, $digest), $checks)) ? null : $refusal;
    }

    /**
     * Return the allow statements of the document, or null when it cannot be
     * read.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Policy|null  $document
     * @return list<\SineMacula\Laravel\Authorization\Evaluation\Statement>|null
     */
    public static function allowsOf(?EvaluationPolicy $document): ?array
    {
        $isAllow = static fn (Statement $statement): bool => $statement->effect === PolicyEffect::ALLOW;

        return $document === null ? null : \array_values(\array_filter($document->statements, $isAllow));
    }

    /**
     * Return why the allows cannot be proved contained: the first refusal of
     * the permission route for an action they name, or
     * `administration.unprovable` for one that names anything but its actions;
     * null when every action passes.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $operation
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationChange  $change
     * @param  list<\SineMacula\Laravel\Authorization\Evaluation\Statement>  $allows
     * @param  bool  $principals
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null
     */
    private static function uncontained(OperationResource $operation, OperationChange $change, array $allows, bool $principals, FurtherChecks $checks): ?DecisionReason
    {
        $actions = [];

        foreach ($allows as $statement) {
            if (!self::isContainable($statement, $principals)) {
                return DecisionReason::ADMINISTRATION_UNPROVABLE;
            }

            $actions = [...$actions, ...$statement->actions ?? []];
        }

        $permissions = \array_map(static fn (string $action): Permission => new Permission(['name' => $action]), \array_values(\array_unique($actions)));

        return Possession::refusalOfEach($operation, $change, $permissions, $checks);
    }

    /**
     * Determine whether the allow names its actions alone: with `actions`, and
     * no resource pattern, condition, or principal, unless principals are
     * weighed by the impact check.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Statement  $statement
     * @param  bool  $principals
     * @return bool
     */
    private static function isContainable(Statement $statement, bool $principals): bool
    {
        if ($statement->actions === null || $statement->conditions !== []) {
            return false;
        }

        $namesNoResource = $statement->resources === null && $statement->notResources === null;

        return $namesNoResource && ($principals || $statement->principals === null);
    }

    /**
     * Return the digest of the document, as stored, or null when it cannot be
     * read.
     *
     * @param  mixed  $document
     * @return string|null
     */
    private static function digestOf(mixed $document): ?string
    {
        try {
            return \is_array($document) ? DocumentDigest::of($document)->digest : null;
        } catch (\JsonException) {
            return null;
        }
    }
}
