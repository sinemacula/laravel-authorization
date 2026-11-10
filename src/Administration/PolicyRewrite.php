<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Administration;

use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Support\InlinePolicies;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\ResourceReference;

/**
 * Whether a delegated rewrite of a policy's document hands out only what the
 * actor may hand out, to holders it administers (AUTHZ-11.1), as the
 * administration stage weighs it for a policy the actor's context owns (see
 * `DefinitionConstraints`). The old document is read as stored, on the write
 * connection, and compared with the new one conservatively (see
 * `DocumentComparison`):
 *
 * - a new document that can only narrow the old one, the same document in
 *   authority terms included, is allowed;
 * - one that lifts a deny, or either document that cannot be read, is refused
 *   as `administration.unprovable`, since what a lifted deny releases cannot be
 *   bounded;
 * - one that adds allows reaches every holder of the policy (see
 *   `AffectedHolders::ofPolicy()`), the principals either document names where
 *   the policy is attached to a resource included: the impact check over them
 *   (see `Impact`), then, for a policy in use as a boundary, the further right
 *   `authorization:administration.unbounded` on the same operation, at its node
 *   and across the policy's reach (see `AdministeredScope::isAllowedAcross()`),
 *   since the rewrite widens the boundary wherever it is set, and the policy
 *   route for the allows it adds across the policy's reach (see `PolicyRoute`),
 *   the grantable route decided on the new document's digest.
 *
 * A rewrite that reaches no holder widens no one, and passes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class PolicyRewrite
{
    /**
     * Return why giving the policy the document, as it would be stored, is
     * refused, or null when it is allowed; a null document stands for one that
     * cannot be read.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $operation
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @param  array<string, mixed>|null  $document
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference  $resource
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null
     */
    public static function refusal(OperationResource $operation, Policy $policy, ?array $document, ResourceReference $resource, FurtherChecks $checks): ?DecisionReason
    {
        $old = DocumentComparison::read(InlinePolicies::stored($policy->getKey())?->document);
        $new = DocumentComparison::read($document);

        if (DocumentComparison::isNarrower($old, $new)) {
            return null;
        }

        if ($new === null || !DocumentComparison::keepsDenies($old, $new)) {
            return DecisionReason::ADMINISTRATION_UNPROVABLE;
        }

        $added  = DocumentComparison::added($old, $new);
        $across = DefinitionConstraints::across($operation, $policy);
        $route  = static fn (): ?DecisionReason => self::unbounded($policy, $across, $resource, $checks)
            ?? PolicyRoute::refusalOf($operation, $across, $policy, $document, $added, $checks);

        return DefinitionConstraints::growth($operation, $resource, AffectedHolders::none()->ofPolicy($policy, [$old, $new]), $checks, $route);
    }

    /**
     * Return `administration.unprovable` when the policy is in use as a
     * boundary and the operation is not also allowed
     * `authorization:administration.unbounded`, at its node and across the
     * policy's reach, the change handing it out (see
     * `AdministeredScope::isAllowedAcross()`).
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationChange  $across
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference  $resource
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null
     */
    private static function unbounded(Policy $policy, OperationChange $across, ResourceReference $resource, FurtherChecks $checks): ?DecisionReason
    {
        /** @var string $table */
        $table = config('authorization.tables.authorizable_boundaries', 'authorizable_boundaries');

        $isBoundary = AuthorizationConnection::connection()->table($table)->useWritePdo()->where('policy_id', $policy->getKey())->exists();

        $isUnbounded = !$isBoundary || AdministeredScope::isAllowedAcross(PackagePermissions::ADMINISTRATION_UNBOUNDED, $resource, $across->scope, $checks);

        return $isUnbounded ? null : DecisionReason::ADMINISTRATION_UNPROVABLE;
    }
}
