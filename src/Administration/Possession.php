<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Administration;

use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;

/**
 * Whether a delegated direct grant of a permission to a principal or an
 * identity hands out only what the actor may hand out (N77), by one of two
 * routes, each decided across the grant's whole reach: its tenant, standing
 * just below it for a grant that reaches the tenants below, or the platform for
 * a platform-wide one, its application, every application's grants alone
 * counting for a grant to every application, and its lifetime.
 *
 * 1. **Provable possession.** In the grant's reach, the actor holds the
 *    permission, or a wildcard covering it, through grants lasting at least as
 *    long as the grant (see `HeldLifetime`), so a permanent grant needs
 *    permanent authority; `check()` of the permission there allows it; and
 *    nothing that denies or caps the actor could limit the permission anywhere
 *    in the reach (see `PossessionLimits`).
 * 2. **Explicit grantability.** `authorization:permission.grantable` is allowed
 *    in the grant's reach on the grant's descriptor (see
 *    `OperationResource::grantable()`), which names the permission, the
 *    grantee, the reach and the expiry, so a policy may allow an exact
 *    delegation the actor does not hold, and a right limited to one application
 *    or to one tenant's node allows no grant beyond it. The right must also
 *    last as long as the grant: held as a permission, through grants lasting
 *    that long; allowed by a policy, through an attachment lasting that long, a
 *    resource policy's never expiring; allowed by a policy the package did not
 *    store, never.
 *
 * When neither holds, the grant is refused as `administration.not_grantable`
 * when the actor does not hold the permission across the grant's reach and
 * lifetime, and as `administration.unprovable` when it does, but its check
 * there is not allowed, or something could limit it, so containment cannot be
 * proved.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class Possession
{
    /**
     * Return why the direct grant of the permission the operation proposes is
     * refused, or null when the actor provably holds what it grants or is
     * explicitly allowed to grant it.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $operation
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationChange  $change
     * @param  string  $permission
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null
     */
    public static function refusal(OperationResource $operation, OperationChange $change, string $permission, FurtherChecks $checks): ?DecisionReason
    {
        $below   = $operation->tenant !== null && $change->scope->includeSubtree;
        $prove   = static fn (): ?DecisionReason => self::unproved($change, $permission, $checks);
        $grant   = static fn (): bool => self::isGrantable($operation, $change, $checks);
        $refusal = TenantScope::within($operation->tenant, $change->scope->application, $prove, $below);

        return $refusal === null || TenantScope::within($operation->tenant, $change->scope->application, $grant, $below) ? null : $refusal;
    }

    /**
     * Return why the actor cannot be proved to hold the permission across the
     * grant, in the grant's reach, which is in place: not at all, or not as
     * long, as `administration.not_grantable`; held, but limited, or its check
     * not allowed, as `administration.unprovable`; or null when it can.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationChange  $change
     * @param  string  $permission
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null
     */
    private static function unproved(OperationChange $change, string $permission, FurtherChecks $checks): ?DecisionReason
    {
        $until = HeldLifetime::of($checks->subject, $permission);

        if ($until === null || $until < $change->lastsUntil()) {
            return DecisionReason::ADMINISTRATION_NOT_GRANTABLE;
        }

        $sources     = $checks->sources($permission);
        $isContained = $sources !== null && $checks->decide($permission)->isAllowed() && !PossessionLimits::isLimited($checks->subject, $permission, $change->scope, $sources);

        return $isContained ? null : DecisionReason::ADMINISTRATION_UNPROVABLE;
    }

    /**
     * Determine whether the actor is allowed the grantable right on the grant's
     * descriptor, in the grant's reach, which is in place, through a source
     * lasting at least as long as the grant.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $operation
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationChange  $change
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @return bool
     */
    private static function isGrantable(OperationResource $operation, OperationChange $change, FurtherChecks $checks): bool
    {
        $decision = $checks->decide(PackagePermissions::PERMISSION_GRANTABLE, $operation->grantable()->toResourceReference());
        $until    = $decision->isAllowed() ? self::allowedUntil($decision, $checks->subject) : null;

        return $until !== null && $until >= $change->lastsUntil();
    }

    /**
     * Return until when what allowed the decision lasts: the grants carrying
     * the right, for an allow by a permission held; else the latest any
     * allowing statement's policy is attached for, a resource policy's never
     * expiring, and one the package did not store never counting; null for
     * none.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Decision  $decision
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return int|null
     */
    private static function allowedUntil(Decision $decision, Subject $subject): ?int
    {
        if ($decision->statements === []) {
            return HeldLifetime::of($subject, PackagePermissions::PERMISSION_GRANTABLE);
        }

        $until = null;

        foreach ($decision->statements as $statement) {
            $lasts = match (true) {
                $statement->resource !== null => \PHP_INT_MAX,
                $statement->policyId !== null => HeldLifetime::ofPolicy($subject, $statement->policyId),
                default                       => null,
            };

            $until = \max($until, $lasts);
        }

        return $until;
    }
}
