<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Administration;

use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;

/**
 * Whether a delegated grant of a permission hands out only what the actor may
 * hand out (N77): a direct grant to a principal or an identity, each permission
 * a granted role carries, each action a policy handed out allows (see
 * `PolicyRoute`), and a permission a change to a definition hands to its
 * holders (see `DefinitionConstraints`), by one of two routes, each decided
 * across the grant's whole reach: its tenant, standing just below it for a
 * grant that reaches the tenants below, or the platform for a platform-wide
 * one, its application, every application's grants alone counting for a grant
 * to every application, and its lifetime.
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
 *    or to one tenant's node allows no grant beyond it; for a reach wider than
 *    its node, nothing that denies or caps the actor anywhere in it may limit
 *    the right, by the rule the action is weighed by (see
 *    `AdministeredScope::isLimited()`), so a right allowed at the platform but
 *    denied in one tenant allows no grant reaching that tenant. The right must
 *    also last as long as the grant: held as a permission, through grants
 *    lasting that long; allowed by a policy, through an attachment lasting that
 *    long, a resource policy's never expiring; allowed by a policy the package
 *    did not store, never.
 *
 * Many permissions, those a role carries or a policy allows, are decided in one
 * pass (see `refusalOfEach()`): the actor's grants, sources and limits read
 * once in the reach for them all (see `HeldLifetime::ofEach()` and
 * `PossessionLimits::limitedEach()`), and the grantable right of each that
 * fails in one more pass, its limits read once for them all, so the cost never
 * grows with the permissions.
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
     * Return why handing out the permission across the change's reach and
     * lifetime is refused, or null when the actor provably holds it there or is
     * explicitly allowed to grant it, on the operation's descriptor naming the
     * permission.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $operation
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationChange  $change
     * @param  \SineMacula\Laravel\Authorization\Models\Permission  $permission
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null
     */
    public static function refusal(OperationResource $operation, OperationChange $change, Permission $permission, FurtherChecks $checks): ?DecisionReason
    {
        return self::refusalOfEach($operation, $change, [$permission], $checks);
    }

    /**
     * Return why handing out the permissions across the change's reach and
     * lifetime is refused: the refusal of the first, in order, the actor can
     * neither be proved to hold there nor is explicitly allowed to grant; or
     * null when every one passes. Every permission is decided in one pass in
     * the reach, the actor's grants, sources and limits read once for them all,
     * and the grantable right of every one that fails in one more, so the cost
     * never grows with the permissions.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $operation
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationChange  $change
     * @param  list<\SineMacula\Laravel\Authorization\Models\Permission>  $permissions
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null
     */
    public static function refusalOfEach(OperationResource $operation, OperationChange $change, array $permissions, FurtherChecks $checks): ?DecisionReason
    {
        $names = \array_values(\array_unique(\array_map(static fn (Permission $permission): string => $permission->name, $permissions)));
        $prove = static fn (): array => self::unproved($change, $names, $checks);

        /** @var array<array-key, \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason> $refusals */
        $refusals = $names === [] ? [] : TenantScope::within($operation->tenant, $change->scope->application, $prove, self::isBelow($operation, $change));
        $first    = static fn (): ?DecisionReason => self::firstUngrantable($operation, $change, $permissions, $refusals, $checks);

        return TenantScope::within($operation->tenant, $change->scope->application, $first, self::isBelow($operation, $change));
    }

    /**
     * Determine whether the actor is allowed the grantable right the descriptor
     * is decided under, on the descriptor, in the change's reach, through a
     * source lasting at least as long as the change, with nothing anywhere in a
     * reach wider than its node that could limit the right.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $operation
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationChange  $change
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $descriptor
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @return bool
     */
    public static function isGrantable(OperationResource $operation, OperationChange $change, OperationResource $descriptor, FurtherChecks $checks): bool
    {
        $grant = static fn (): bool => self::isGrantableFor($change, $descriptor, $checks, new HeldLifetimes($checks->subject));

        return TenantScope::within($operation->tenant, $change->scope->application, $grant, self::isBelow($operation, $change));
    }

    /**
     * Return why the actor cannot be proved to hold each of the permissions
     * across the grant, in the grant's reach, which is in place, keyed by the
     * permission, leaving out each it can: not at all, or not as long, as
     * `administration.not_grantable`; held, but limited, or its check not
     * allowed, as `administration.unprovable`.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationChange  $change
     * @param  list<string>  $permissions
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @return array<array-key, \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason>
     */
    private static function unproved(OperationChange $change, array $permissions, FurtherChecks $checks): array
    {
        $lifetimes = HeldLifetime::ofEach($checks->subject, $permissions);
        $refusals  = [];
        $held      = [];

        foreach ($permissions as $permission) {
            $until = $lifetimes[$permission];

            if ($until === null || $until < $change->lastsUntil()) {
                $refusals[$permission] = DecisionReason::ADMINISTRATION_NOT_GRANTABLE;

                continue;
            }

            $sources = $checks->sources($permission);

            if ($sources === null || !$checks->decide($permission)->isAllowed()) {
                $refusals[$permission] = DecisionReason::ADMINISTRATION_UNPROVABLE;

                continue;
            }

            $held[$permission] = $sources;
        }

        foreach (\array_keys(\array_filter(PossessionLimits::limitedEach($checks->subject, $change->scope, $held))) as $permission) {
            $refusals[$permission] = DecisionReason::ADMINISTRATION_UNPROVABLE;
        }

        return $refusals;
    }

    /**
     * Return the refusal of the first of the permissions, in order, that the
     * possession route refused and the actor is not explicitly allowed to
     * grant, in the change's reach, which is in place; or null when there is
     * none.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $operation
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationChange  $change
     * @param  list<\SineMacula\Laravel\Authorization\Models\Permission>  $permissions
     * @param  array<array-key, \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason>  $refusals
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null
     */
    private static function firstUngrantable(OperationResource $operation, OperationChange $change, array $permissions, array $refusals, FurtherChecks $checks): ?DecisionReason
    {
        $lifetimes = new HeldLifetimes($checks->subject);

        foreach ($permissions as $permission) {
            $refusal = $refusals[$permission->name] ?? null;

            if ($refusal !== null && !self::isGrantableFor($change, $operation->grantable($permission), $checks, $lifetimes)) {
                return $refusal;
            }
        }

        return null;
    }

    /**
     * Determine whether the actor may grant through the descriptor in the
     * change's reach, which is in place: the grantable right it is decided
     * under is allowed on it through a source lasting as long as the change
     * (see `isAllowedFor()`), and nothing anywhere in a reach wider than its
     * node could limit the right (see `AdministeredScope::isLimited()`), read
     * once in the decision for every descriptor of the right.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationChange  $change
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $descriptor
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @param  \SineMacula\Laravel\Authorization\Administration\HeldLifetimes  $lifetimes
     * @return bool
     */
    private static function isGrantableFor(OperationChange $change, OperationResource $descriptor, FurtherChecks $checks, HeldLifetimes $lifetimes): bool
    {
        return self::isAllowedFor($change, $descriptor, $checks, $lifetimes) && !AdministeredScope::isLimited($descriptor->action, $change->scope, $checks);
    }

    /**
     * Determine whether the actor is allowed the grantable right on the
     * descriptor, in the change's reach, which is in place, through a source
     * lasting at least as long as the change, each lifetime read once through
     * the lifetimes given.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationChange  $change
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $descriptor
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @param  \SineMacula\Laravel\Authorization\Administration\HeldLifetimes  $lifetimes
     * @return bool
     */
    private static function isAllowedFor(OperationChange $change, OperationResource $descriptor, FurtherChecks $checks, HeldLifetimes $lifetimes): bool
    {
        $decision = $checks->decide($descriptor->action, $descriptor->toResourceReference());
        $until    = $decision->isAllowed() ? self::allowedUntil($decision, $descriptor->action, $lifetimes) : null;

        return $until !== null && $until >= $change->lastsUntil();
    }

    /**
     * Determine whether the change's reach stands just below its tenant: it
     * reaches the tenants below a tenant.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationResource  $operation
     * @param  \SineMacula\Laravel\Authorization\Administration\OperationChange  $change
     * @return bool
     */
    private static function isBelow(OperationResource $operation, OperationChange $change): bool
    {
        return $operation->tenant !== null && $change->scope->includeSubtree;
    }

    /**
     * Return until when what allowed the decision lasts: the grants carrying
     * the right, for an allow by a permission held; else the latest any
     * allowing statement's policy is attached for, a resource policy's never
     * expiring, and one the package did not store never counting; null for
     * none.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Decision  $decision
     * @param  string  $right
     * @param  \SineMacula\Laravel\Authorization\Administration\HeldLifetimes  $lifetimes
     * @return int|null
     */
    private static function allowedUntil(Decision $decision, string $right, HeldLifetimes $lifetimes): ?int
    {
        if ($decision->statements === []) {
            return $lifetimes->of($right);
        }

        $until = null;

        foreach ($decision->statements as $statement) {
            $lasts = match (true) {
                $statement->resource !== null => \PHP_INT_MAX,
                $statement->policyId !== null => $lifetimes->ofPolicy($statement->policyId),
                default                       => null,
            };

            $until = \max($until, $lasts);
        }

        return $until;
    }
}
