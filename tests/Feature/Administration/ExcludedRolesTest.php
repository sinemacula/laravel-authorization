<?php

declare(strict_types = 1);

namespace Tests\Feature\Administration;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Administration\ExcludedRoles;
use SineMacula\Laravel\Authorization\Administration\FurtherChecks;
use SineMacula\Laravel\Authorization\Administration\OperationResource;
use SineMacula\Laravel\Authorization\Evaluation\CheckContext;
use SineMacula\Laravel\Authorization\Evaluation\CheckSources;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\SessionCaps;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\PackagePermissions as Actions;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for `ExcludedRoles`: the rank and administered-scope rules a
 * pair of mutually exclusive roles declared or removed is weighed by.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExcludedRoles::class)]
final class ExcludedRolesTest extends TestCase
{
    /**
     * Both roles of a pair must be junior to the actor, ranked 2, the more
     * senior of the two weighed: an unranked role is junior to everyone, a peer
     * or a senior role refuses the change, declared or removed, and with the
     * rank rule off nothing is refused by rank.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testBothRolesMustBeJuniorToTheActor(): void
    {
        $unranked = Role::query()->create(['name' => 'unranked']);
        $junior   = Role::query()->create(['name' => 'junior', 'rank' => 9]);
        $peer     = Role::query()->create(['name' => 'peer', 'rank' => 2]);
        $senior   = Role::query()->create(['name' => 'senior', 'rank' => 1]);

        foreach ([Actions::ROLE_EXCLUSION_DECLARE, Actions::ROLE_EXCLUSION_REMOVE] as $action) {
            self::assertNull(self::refusal($action, $unranked, Role::query()->create(['name' => 'free-' . $action])), $action);
            self::assertNull(self::refusal($action, $unranked, $junior), $action);
            self::assertNull(self::refusal($action, $junior, $unranked), $action);
            self::assertSame(DecisionReason::ADMINISTRATION_RANK, self::refusal($action, $junior, $peer), $action);
            self::assertSame(DecisionReason::ADMINISTRATION_RANK, self::refusal($action, $peer, $junior), $action);
            self::assertSame(DecisionReason::ADMINISTRATION_RANK, self::refusal($action, $unranked, $senior), $action);
            self::assertSame(DecisionReason::ADMINISTRATION_RANK, self::refusal($action, $senior, $unranked), $action);
        }

        config(['authorization.rank.enabled' => false]);

        self::assertNull(self::refusal(Actions::ROLE_EXCLUSION_DECLARE, $junior, $senior));
    }

    /**
     * A removal lifts the pair across its owner's whole reach, so it is refused
     * as `administration.scope` when the actor does not administer it, before
     * its rank is weighed; a declaration only adds a constraint and is never
     * weighed across its reach.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARemovalIsWeighedAcrossTheOwnersReach(): void
    {
        $junior   = Role::query()->create(['name' => 'junior', 'rank' => 9]);
        $other    = Role::query()->create(['name' => 'other', 'rank' => 8]);
        $senior   = Role::query()->create(['name' => 'senior', 'rank' => 1]);
        $refusing = static fn (string $asked): Decision => $asked === Actions::ROLE_EXCLUSION_REMOVE || $asked === Actions::ROLE_EXCLUSION_DECLARE
            ? self::denied()
            : Decision::allow(DecisionStage::ALLOW);

        self::assertSame(DecisionReason::ADMINISTRATION_SCOPE, self::refusal(Actions::ROLE_EXCLUSION_REMOVE, $junior, $other, $refusing));
        self::assertSame(DecisionReason::ADMINISTRATION_SCOPE, self::refusal(Actions::ROLE_EXCLUSION_REMOVE, $junior, $senior, $refusing));
        self::assertNull(self::refusal(Actions::ROLE_EXCLUSION_DECLARE, $junior, $other, $refusing));
    }

    /**
     * A removal made while impersonating needs
     * `authorization:administration.impersonated` across the owner's whole
     * reach, or is refused as `administration.impersonating`; a declaration
     * made while impersonating is weighed at its node alone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnImpersonatedRemovalNeedsTheImpersonatedRightAcrossTheReach(): void
    {
        $junior       = Role::query()->create(['name' => 'junior', 'rank' => 9]);
        $other        = Role::query()->create(['name' => 'other', 'rank' => 8]);
        $impersonator = new Reference('stub_identity', 'operator');
        $refusing     = static fn (string $asked): Decision => $asked === Actions::ADMINISTRATION_IMPERSONATED ? self::denied() : Decision::allow(DecisionStage::ALLOW);

        self::assertSame(DecisionReason::ADMINISTRATION_IMPERSONATING, self::refusal(Actions::ROLE_EXCLUSION_REMOVE, $junior, $other, $refusing, $impersonator));
        self::assertNull(self::refusal(Actions::ROLE_EXCLUSION_REMOVE, $junior, $other, null, $impersonator));
        self::assertNull(self::refusal(Actions::ROLE_EXCLUSION_REMOVE, $junior, $other, $refusing));
        self::assertNull(self::refusal(Actions::ROLE_EXCLUSION_DECLARE, $junior, $other, $refusing, $impersonator));
    }

    /**
     * A change naming no other role, which the service never builds, cannot be
     * weighed, and is unprovable.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChangeNamingNoOtherRoleIsUnprovable(): void
    {
        $role      = Role::query()->create(['name' => 'junior', 'rank' => 9]);
        $operation = OperationResource::definition(Actions::ROLE_EXCLUSION_DECLARE, $role);

        self::assertSame(DecisionReason::ADMINISTRATION_UNPROVABLE, ExcludedRoles::refusal($operation, $role, null, $operation->toResourceReference(), self::checks()));
        self::assertSame(
            DecisionReason::ADMINISTRATION_UNPROVABLE,
            ExcludedRoles::refusal($operation, $role, StubIdentity::query()->create(['id' => 'record']), $operation->toResourceReference(), self::checks()),
        );
    }

    /**
     * Return why the pair's change is refused, the actor ranked 2 at the
     * platform, every further check allowed unless another decides them, and
     * impersonated by the reference given.
     *
     * @param  string  $action
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $excluded
     * @param  (\Closure(string, \SineMacula\Laravel\Authorization\Support\ResourceReference|null): \SineMacula\Laravel\Authorization\Evaluation\Decision)|null  $decide
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $impersonator
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null
     *
     * @throws \Throwable
     */
    private static function refusal(string $action, Role $role, Role $excluded, ?\Closure $decide = null, ?Reference $impersonator = null): ?DecisionReason
    {
        $operation = OperationResource::exclusion($action, $role, $excluded)->actedBy($impersonator, 'operation-1');

        return ExcludedRoles::refusal($operation, $role, $excluded, $operation->toResourceReference(), self::checks($decide));
    }

    /**
     * Return the further checks of the actor, ranked 2, deciding every check
     * through the closure given, or allowing it.
     *
     * @param  (\Closure(string, \SineMacula\Laravel\Authorization\Support\ResourceReference|null): \SineMacula\Laravel\Authorization\Evaluation\Decision)|null  $decide
     * @return \SineMacula\Laravel\Authorization\Administration\FurtherChecks
     *
     * @throws \Throwable
     */
    private static function checks(?\Closure $decide = null): FurtherChecks
    {
        $actor = StubIdentity::query()->firstOrCreate(['id' => 'admin']);

        if (!$actor->hasRole('chief')) {
            app(GrantService::class)->grantRole($actor, Role::query()->create(['name' => 'chief', 'rank' => 2]));
            app(GrantService::class)->grantPermission($actor, Permission::query()->firstOrCreate(['name' => 'authorization:*']));
        }

        $decide ??= static fn (): Decision => Decision::allow(DecisionStage::ALLOW);

        return new FurtherChecks(new Subject($actor, $actor), $decide, static fn (): CheckSources => self::noSources(), null);
    }

    /**
     * Return a decision that refuses, as no statement matching does.
     *
     * @return \SineMacula\Laravel\Authorization\Evaluation\Decision
     */
    private static function denied(): Decision
    {
        return Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT);
    }

    /**
     * Return the sources of a check that reads no policy, boundary, guardrail
     * or session cap.
     *
     * @return \SineMacula\Laravel\Authorization\Evaluation\CheckSources
     */
    private static function noSources(): CheckSources
    {
        return new CheckSources([], null, [], new CheckContext, static fn (): ?string => null, new SessionCaps);
    }
}
