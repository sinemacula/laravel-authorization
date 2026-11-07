<?php

declare(strict_types = 1);

namespace Tests\Feature\Administration;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Administration\OperationConstraints;
use SineMacula\Laravel\Authorization\Administration\OperationResource;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\Enums\TraceOutcome;
use SineMacula\Laravel\Authorization\Evaluation\RequirementFreshness;
use SineMacula\Laravel\Authorization\Evaluation\TraceEntry;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for `OperationConstraints`, the administration stage of a
 * decision.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(OperationConstraints::class)]
final class OperationConstraintsTest extends TestCase
{
    /**
     * A decision the stage does not apply to is returned as it is: a denial, a
     * check with no resource or another resource, and a check of another action
     * than the operation's; none of them decides a further check.
     *
     * @return void
     */
    public function testLeavesEveryOtherDecisionAsItIs(): void
    {
        $allowed   = Decision::allow(DecisionStage::ALLOW);
        $denied    = Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT);
        $operation = self::grant()->toResourceReference();
        $decide    = static fn (string $action): Decision => self::fail("No further check was expected, {$action} was decided.");

        self::assertSame($denied, OperationConstraints::weigh($denied, PackagePermissions::ROLE_GRANT, $operation, $decide));
        self::assertSame($allowed, OperationConstraints::weigh($allowed, PackagePermissions::ROLE_GRANT, null, $decide));
        self::assertSame($allowed, OperationConstraints::weigh($allowed, PackagePermissions::ROLE_GRANT, ResourceReference::record('post', '1'), $decide));
        self::assertSame($allowed, OperationConstraints::weigh($allowed, PackagePermissions::ROLE_REVOKE, $operation, $decide));
    }

    /**
     * An allowed operation that may widen authority is refused as unprovable at
     * the administration stage, its trace ending with the refusing constraint
     * by its code after every step the allow took, and its freshness kept.
     *
     * @return void
     */
    public function testAWideningOperationIsRefusedAsUnprovable(): void
    {
        $step     = new TraceEntry(DecisionStage::ALLOW, TraceOutcome::HELD, permission: PackagePermissions::ROLE_GRANT);
        $fresh    = new RequirementFreshness('session-1');
        $allowed  = Decision::allow(DecisionStage::ALLOW, [], [$step])->withFreshness($fresh);
        $decision = OperationConstraints::weigh($allowed, PackagePermissions::ROLE_GRANT, self::grant()->toResourceReference(), static fn (): Decision => $allowed);

        self::assertFalse($decision->isAllowed());
        self::assertSame(DecisionReason::ADMINISTRATION_UNPROVABLE, $decision->reason);
        self::assertSame(DecisionStage::ADMINISTRATION, $decision->stage);
        self::assertSame([], $decision->statements);
        self::assertEquals([$step, new TraceEntry(DecisionStage::ADMINISTRATION, TraceOutcome::REFUSED, null, [], 'administration.unprovable')], $decision->trace);
        self::assertSame($fresh, $decision->freshness);
    }

    /**
     * An allowed operation that can only narrow passes, with one satisfied step
     * at the administration stage.
     *
     * @return void
     */
    public function testANarrowingOperationPasses(): void
    {
        $allowed  = Decision::allow(DecisionStage::ALLOW);
        $decision = OperationConstraints::weigh($allowed, PackagePermissions::PERMISSION_REVOKE, self::revoke()->toResourceReference(), static fn (): Decision => $allowed);

        self::assertTrue($decision->isAllowed());
        self::assertSame(DecisionStage::ALLOW, $decision->stage);
        self::assertEquals([new TraceEntry(DecisionStage::ADMINISTRATION, TraceOutcome::SATISFIED)], $decision->trace);
    }

    /**
     * An operation made while impersonating is refused as impersonating unless
     * `authorization:administration.impersonated` is also allowed on it, which
     * is decided as a further check; then the other constraints still apply.
     *
     * @return void
     */
    public function testAnImpersonatedOperationNeedsTheImpersonatedRight(): void
    {
        $allowed = Decision::allow(DecisionStage::ALLOW);
        $refused = Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT);
        $revoke  = self::revoke()->actedBy(new Reference('support', '9'))->toResourceReference();
        $grant   = self::grant()->actedBy(new Reference('support', '9'))->toResourceReference();
        $asked   = [];
        $decide  = static function (string $action) use (&$asked, $refused): Decision {
            $asked[] = $action;

            return $refused;
        };

        $decision = OperationConstraints::weigh($allowed, PackagePermissions::PERMISSION_REVOKE, $revoke, $decide);

        self::assertSame(DecisionReason::ADMINISTRATION_IMPERSONATING, $decision->reason);
        self::assertSame([PackagePermissions::ADMINISTRATION_IMPERSONATED], $asked);
        self::assertTrue(OperationConstraints::weigh($allowed, PackagePermissions::PERMISSION_REVOKE, $revoke, static fn (): Decision => $allowed)->isAllowed());
        $widening = OperationConstraints::weigh($allowed, PackagePermissions::ROLE_GRANT, $grant, static fn (): Decision => $allowed);

        self::assertSame(DecisionReason::ADMINISTRATION_UNPROVABLE, $widening->reason);
    }

    /**
     * Through `check()`, the stage follows the allow: a subject holding the
     * action is refused a widening operation as unprovable and allowed a
     * narrowing one, and one not holding it is refused as the allow stage
     * refuses it, the stage never reached.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheStageFollowsTheAllowThroughCheck(): void
    {
        $admin = StubIdentity::create(['id' => 'admin-1']);
        $other = StubIdentity::create(['id' => 'other-1']);

        $admin->givePermission(Permission::create(['name' => 'authorization:*']));

        $grant = Authorization::for($admin)->check(PackagePermissions::ROLE_GRANT, self::grant());

        self::assertSame(DecisionReason::ADMINISTRATION_UNPROVABLE, $grant->reason);
        self::assertSame(DecisionStage::ADMINISTRATION, $grant->stage);
        self::assertStringContainsString('[administration] administration.unprovable: refused', $grant->explain());
        self::assertTrue(Authorization::for($admin)->check(PackagePermissions::PERMISSION_REVOKE, self::revoke())->isAllowed());
        self::assertTrue(Authorization::for($admin)->check(PackagePermissions::ROLE_GRANT)->isAllowed());
        self::assertSame(DecisionReason::NO_MATCH, ActingContext::for($other)->check(self::revoke())->reason);
        self::assertSame(DecisionStage::IMPLICIT, ActingContext::for($other)->check(self::revoke())->stage);
    }

    /**
     * Return a proposed grant of a role.
     *
     * @return \SineMacula\Laravel\Authorization\Administration\OperationResource
     */
    private static function grant(): OperationResource
    {
        return OperationResource::grant(PackagePermissions::ROLE_GRANT, new Reference('user', '1'), Role::query()->firstOrCreate(['name' => 'editor']), GrantScope::platform());
    }

    /**
     * Return a proposed revocation of a permission.
     *
     * @return \SineMacula\Laravel\Authorization\Administration\OperationResource
     */
    private static function revoke(): OperationResource
    {
        $permission = Permission::query()->firstOrCreate(['name' => 'posts:edit']);

        return OperationResource::revoke(PackagePermissions::PERMISSION_REVOKE, new Reference('user', '1'), $permission, GrantScope::platform());
    }
}
