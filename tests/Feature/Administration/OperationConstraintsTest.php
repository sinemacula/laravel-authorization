<?php

declare(strict_types = 1);

namespace Tests\Feature\Administration;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Administration\FurtherChecks;
use SineMacula\Laravel\Authorization\Administration\OperationConstraints;
use SineMacula\Laravel\Authorization\Administration\OperationResource;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Evaluation\CheckContext;
use SineMacula\Laravel\Authorization\Evaluation\CheckSources;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\Enums\TraceOutcome;
use SineMacula\Laravel\Authorization\Evaluation\HeldPermission;
use SineMacula\Laravel\Authorization\Evaluation\RequirementFreshness;
use SineMacula\Laravel\Authorization\Evaluation\RequirementResult;
use SineMacula\Laravel\Authorization\Evaluation\SessionCaps;
use SineMacula\Laravel\Authorization\Evaluation\TraceEntry;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Services\RoleService;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\AuthorizationScope;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use Tests\Concerns\PreviewsSubjects;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubRequirementChecker;
use Tests\Feature\Stubs\StubTenant;
use Tests\Feature\Stubs\StubTenantTree;
use Tests\Fixtures\BulkChecks\FailingTenantTree;
use Tests\TestCase;

/**
 * Feature tests for `OperationConstraints`, the administration stage of a
 * decision.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(OperationConstraints::class)]
final class OperationConstraintsTest extends TestCase
{
    use PreviewsSubjects;

    /** @var list<array{string, string|null, bool, array{string, string}|null}> Each further check asked: its action, the application, whether below, and the tenant in place. */
    private array $asked = [];

    /**
     * A decision the stage does not apply to is returned as it is: a denial, a
     * check with no resource or another resource, a check of another action
     * than the operation's, and a grantable descriptor; none of them decides a
     * further check.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testLeavesEveryOtherDecisionAsItIs(): void
    {
        $allowed    = Decision::allow(DecisionStage::ALLOW);
        $denied     = Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT);
        $operation  = self::roleGrant()->toResourceReference();
        $descriptor = self::permissionGrant(self::user('user'))->grantable()->toResourceReference();
        $checks     = $this->checks(self::user('admin'), self::unexpected(...));

        self::assertSame($denied, OperationConstraints::weigh($denied, PackagePermissions::ROLE_GRANT, $operation, $checks));
        self::assertSame($allowed, OperationConstraints::weigh($allowed, PackagePermissions::ROLE_GRANT, null, $checks));
        self::assertSame($allowed, OperationConstraints::weigh($allowed, PackagePermissions::ROLE_GRANT, ResourceReference::record('post', '1'), $checks));
        self::assertSame($allowed, OperationConstraints::weigh($allowed, PackagePermissions::ROLE_REVOKE, $operation, $checks));
        self::assertSame($allowed, OperationConstraints::weigh($allowed, PackagePermissions::PERMISSION_GRANTABLE, $descriptor, $checks));
    }

    /**
     * An allowed operation on anything but a subject that may widen authority
     * and cannot be proved, such as detaching a denying policy from a role, is
     * refused as unprovable at the administration stage, its trace ending with
     * the refusing constraint by its code after every step the allow took, and
     * its freshness and the requirements it read kept; one that can only narrow
     * passes, with one satisfied step.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnOperationOnARoleIsRefusedUnlessItNarrows(): void
    {
        $step     = new TraceEntry(DecisionStage::ALLOW, TraceOutcome::HELD, permission: PackagePermissions::PERMISSION_GRANT);
        $fresh    = new RequirementFreshness('session-1');
        $allowed  = Decision::allow(DecisionStage::ALLOW, [], [$step])->withFreshness($fresh, ['multifactor']);
        $role     = Role::query()->create(['name' => 'editor']);
        $edit     = Permission::query()->create(['name' => 'posts:edit']);
        $checks   = $this->checks(self::user('admin'), self::unexpected(...));
        $grant    = OperationResource::revoke(PackagePermissions::POLICY_DETACH, $role, self::denying(), GrantScope::platform());
        $revoke   = OperationResource::revoke(PackagePermissions::PERMISSION_REVOKE, $role, $edit, GrantScope::platform());
        $decision = OperationConstraints::weigh($allowed, PackagePermissions::POLICY_DETACH, $grant->toResourceReference(), $checks);

        self::assertFalse($decision->isAllowed());
        self::assertSame(DecisionReason::ADMINISTRATION_UNPROVABLE, $decision->reason);
        self::assertSame(DecisionStage::ADMINISTRATION, $decision->stage);
        self::assertSame([], $decision->statements);
        self::assertEquals([$step, new TraceEntry(DecisionStage::ADMINISTRATION, TraceOutcome::REFUSED, null, [], 'administration.unprovable')], $decision->trace);
        self::assertSame($fresh, $decision->freshness);
        self::assertSame(['multifactor'], $decision->requirementsRead);

        $narrowed = OperationConstraints::weigh(Decision::allow(DecisionStage::ALLOW), PackagePermissions::PERMISSION_REVOKE, $revoke->toResourceReference(), $checks);

        self::assertTrue($narrowed->isAllowed());
        self::assertSame(DecisionStage::ALLOW, $narrowed->stage);
        self::assertEquals([new TraceEntry(DecisionStage::ADMINISTRATION, TraceOutcome::SATISFIED)], $narrowed->trace);
    }

    /**
     * An operation made while impersonating is refused as impersonating unless
     * `authorization:administration.impersonated` is also allowed on it, which
     * is decided as a further check on the same resource; then the other
     * constraints still apply.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnImpersonatedOperationNeedsTheImpersonatedRight(): void
    {
        $allowed  = Decision::allow(DecisionStage::ALLOW);
        $revoke   = self::revoke(self::user('user'))->actedBy(new Reference('support', '9'))->toResourceReference();
        $resource = null;
        $refusing = $this->checks(self::senior('admin'), static function (string $action, ?ResourceReference $on) use (&$resource): Decision {
            $resource = $on;

            return Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT);
        });

        self::assertSame(DecisionReason::ADMINISTRATION_IMPERSONATING, OperationConstraints::weigh($allowed, PackagePermissions::PERMISSION_REVOKE, $revoke, $refusing)->reason);
        self::assertSame(PackagePermissions::ADMINISTRATION_IMPERSONATED, $this->asked[0][0]);
        self::assertSame($revoke, $resource);

        $allowing = $this->checks(self::senior('admin'), static fn (): Decision => $allowed);

        self::assertTrue(OperationConstraints::weigh($allowed, PackagePermissions::PERMISSION_REVOKE, $revoke, $allowing)->isAllowed());
    }

    /**
     * The decision that leaves the stage carries every authentication
     * requirement its further checks read, allowed or refused, beside its own,
     * once each, sorted, and may be reused no longer than the earliest of them
     * stays met.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheRequirementsFurtherChecksReadAreCarried(): void
    {
        $own     = new RequirementFreshness('session-1', new \DateTimeImmutable('2026-11-06 13:00:00'));
        $noon    = new RequirementFreshness('session-1', new \DateTimeImmutable('2026-11-06 12:00:00'));
        $allowed = Decision::allow(DecisionStage::ALLOW)->withFreshness($own, ['phishing_resistant']);
        $revoke  = self::revoke(self::user('user'))->actedBy(new Reference('support', '9'))->toResourceReference();
        $further = static fn (): Decision => Decision::allow(DecisionStage::ALLOW)->withFreshness($noon, ['multifactor']);
        $refused = static fn (): Decision => Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT)->withFreshness($noon, ['multifactor']);

        $satisfied = OperationConstraints::weigh($allowed, PackagePermissions::PERMISSION_REVOKE, $revoke, $this->checks(self::senior('admin'), $further));
        $refusal   = OperationConstraints::weigh($allowed, PackagePermissions::PERMISSION_REVOKE, $revoke, $this->checks(self::senior('admin'), $refused));

        self::assertTrue($satisfied->isAllowed());
        self::assertSame(['multifactor', 'phishing_resistant'], $satisfied->requirementsRead);
        self::assertSame($noon, $satisfied->freshness);
        self::assertSame(DecisionReason::ADMINISTRATION_IMPERSONATING, $refusal->reason);
        self::assertSame(['multifactor', 'phishing_resistant'], $refusal->requirementsRead);
        self::assertSame($noon, $refusal->freshness);
    }

    /**
     * An authentication requirement the impersonated right needs is read by the
     * stage, so it is part of the operation's decision: while it is met, the
     * operation's action is listed as conditional on it, and its check may be
     * reused no longer than the requirement stays met; while it is not, the
     * action is not listed, and its check is refused as impersonating.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARequirementTheImpersonatedRightNeedsIsCarried(): void
    {
        $admin     = self::senior('admin');
        $until     = new \DateTimeImmutable('+1 hour');
        $operation = self::revoke(self::user('user'))->actedBy(new Reference('support', '9'));
        $scope     = AuthorizationScope::current()->withResource($operation);

        $admin->givePermission(Permission::query()->create(['name' => PackagePermissions::PERMISSION_REVOKE]));
        self::attachStatements($admin, 'impersonated', [self::requiring(PackagePermissions::ADMINISTRATION_IMPERSONATED)]);

        $manager = $this->signIn($admin, checker: new StubRequirementChecker(RequirementResult::met($until)));
        $listed  = $manager->heldPermissionsFor(null, $scope);
        $held    = \array_column(\array_map(static fn (HeldPermission $permission): array => [$permission->action, $permission->requirements], $listed), 1, 0);

        self::assertSame(['multifactor'], $held[PackagePermissions::PERMISSION_REVOKE] ?? null);
        self::assertTrue($manager->check(PackagePermissions::PERMISSION_REVOKE, $operation)->isAllowed());
        self::assertSame(['multifactor'], $manager->lastDecision()?->requirementsRead);
        self::assertEquals($until, $manager->lastDecision()->freshness?->metUntil);

        $unmet = $this->signIn($admin, checker: new StubRequirementChecker(RequirementResult::unmet(['multifactor'])));
        $check = $unmet->check(PackagePermissions::PERMISSION_REVOKE, $operation);

        self::assertNotContains(PackagePermissions::PERMISSION_REVOKE, $unmet->permissionsFor(null, $scope));
        self::assertSame(DecisionReason::ADMINISTRATION_IMPERSONATING, $check->reason);
        self::assertSame(['multifactor'], $check->requirementsRead);
    }

    /**
     * No owner stands in the way of a change to a grant row (N79): a revocation
     * of a tenant's row, or of a platform-wide one, passes the stage whatever
     * tenant the check is made from, the action's own decision having admitted
     * it; and a change that fails both the scope and the rank rule is refused
     * as out of scope, the first constraint weighed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testNoOwnerStandsInTheWayOfAGrantRow(): void
    {
        $allowed = Decision::allow(DecisionStage::ALLOW);
        $tenant  = new Reference('tenant', 'a');
        $user    = self::user('user');
        $edit    = Permission::query()->create(['name' => 'posts:edit']);
        $revoke  = OperationResource::revoke(PackagePermissions::PERMISSION_REVOKE, $user, $edit, new GrantScope($tenant))->toResourceReference();
        $wide    = OperationResource::revoke(PackagePermissions::PERMISSION_REVOKE, $user, $edit, GrantScope::platform())->toResourceReference();
        $checks  = $this->checks(self::senior('admin'), self::unexpected(...));

        self::assertTrue(OperationConstraints::weigh($allowed, PackagePermissions::PERMISSION_REVOKE, $revoke, $checks)->isAllowed());
        $elsewhere = static fn (): Decision => OperationConstraints::weigh($allowed, PackagePermissions::PERMISSION_REVOKE, $wide, $checks);

        self::assertTrue(TenantScope::within(new Reference('tenant', 'b'), null, $elsewhere)->isAllowed());

        $reader  = Policy::create(['name' => 'reader', 'document' => ['statements' => []]]);
        $grant   = OperationResource::grant(PackagePermissions::POLICY_ATTACH, self::senior('peer'), $reader, new GrantScope($tenant));
        $denying = $this->checks(self::senior('admin'), static fn (): Decision => Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT));

        self::assertSame(DecisionReason::ADMINISTRATION_SCOPE, self::weigh(PackagePermissions::POLICY_ATTACH, $grant->toResourceReference(), $denying)->reason);
    }

    /**
     * A change that may widen authority decides its action again across its
     * whole reach, in the grant's tenant, just below it when the grant reaches
     * below, and in the grant's application, and is refused as out of scope
     * when that is not allowed; a change that only narrows is not decided
     * again.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAWideningChangeIsDecidedAcrossItsWholeReach(): void
    {
        $allowed  = Decision::allow(DecisionStage::ALLOW);
        $tenant   = new Reference('tenant', 'a');
        $user     = self::user('user');
        $reader   = Policy::create(['name' => 'reader', 'document' => ['statements' => []]]);
        $grant    = OperationResource::grant(PackagePermissions::POLICY_ATTACH, $user, $reader, new GrantScope($tenant, 'admin'));
        $node     = OperationResource::grant(PackagePermissions::POLICY_ATTACH, $user, $reader, new GrantScope($tenant, null, false));
        $platform = OperationResource::grant(PackagePermissions::POLICY_ATTACH, $user, $reader, GrantScope::platform());
        $denying  = $this->checks(self::senior('admin'), static fn (): Decision => Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT));

        self::assertSame(DecisionReason::ADMINISTRATION_SCOPE, self::weigh(PackagePermissions::POLICY_ATTACH, $grant->toResourceReference(), $denying)->reason);
        self::assertSame([PackagePermissions::POLICY_ATTACH, 'admin', true, ['tenant', 'a']], $this->asked[0]);

        $allowing = $this->checks(self::senior('admin'), static fn (): Decision => $allowed);

        self::assertNull(self::weigh(PackagePermissions::POLICY_ATTACH, $node->toResourceReference(), $allowing)->reason);
        self::assertSame([PackagePermissions::POLICY_ATTACH, null, false, ['tenant', 'a']], $this->asked[1]);

        $platformChecks = $this->checks(self::senior('admin'), static fn (): Decision => $allowed);

        OperationConstraints::weigh($allowed, PackagePermissions::POLICY_ATTACH, $platform->toResourceReference(), $platformChecks);

        self::assertSame([PackagePermissions::POLICY_ATTACH, null, false, null], $this->asked[2]);
        self::assertCount(3, $this->asked);
    }

    /**
     * The administered scope is the whole reach (N79): an actor allowed
     * `authorization:*` at the platform, but holding a role in one tenant whose
     * policy denies `authorization:role.grant`, is refused a platform-wide role
     * grant, and a subtree grant from a parent of that tenant, as out of scope,
     * though each is allowed at the node it is decided at; a node-only grant in
     * the parent reaches no further than its decision, so it is allowed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAWiderReachIsRefusedWhereTheActionIsDeniedInATenantItReaches(): void
    {
        $admin  = self::senior('admin');
        $parent = StubTenant::query()->create(['id' => 'parent', 'name' => 'parent']);
        $denied = StubTenant::query()->create(['id' => 't0', 'name' => 't0']);
        $named  = Role::query()->create(['name' => 'named', 'rank' => 8]);
        $role   = Role::query()->create(['name' => 'restricted', 'rank' => 8]);
        $policy = Policy::create(['name' => 'restricting', 'document' => ['statements' => [['effect' => 'deny', 'actions' => [PackagePermissions::ROLE_GRANT]]]]]);

        $this->app?->instance(TenantTree::class, (new StubTenantTree)->put(Reference::of($denied), Reference::of($parent)));

        $admin->givePermission(Permission::create(['name' => 'authorization:*']));

        GrantService::instance()?->attachPolicy($role, $policy);
        GrantService::instance()?->grantRole($admin, $role, tenant: $denied);

        $grantee = self::user('u1');
        $check   = static fn (GrantScope $scope): Decision => ActingContext::for($admin)->check(OperationResource::grant(PackagePermissions::ROLE_GRANT, $grantee, $named, $scope));

        self::assertSame(DecisionReason::ADMINISTRATION_SCOPE, $check(GrantScope::platform())->reason);
        self::assertSame(DecisionStage::ADMINISTRATION, $check(GrantScope::platform())->stage);
        self::assertSame(DecisionReason::ADMINISTRATION_SCOPE, $check(new GrantScope(Reference::of($parent)))->reason);
        self::assertTrue($check(new GrantScope(Reference::of($parent), null, false))->isAllowed());
    }

    /**
     * Rank weighs every change to a subject, a revocation included: an actor
     * not strictly senior is refused as rank, a grantee or actor whose rank
     * cannot be read as uncomparable, and with rank off neither is.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRankWeighsEveryChangeToASubject(): void
    {
        $allowed  = Decision::allow(DecisionStage::ALLOW);
        $peer     = self::revoke(self::senior('peer'))->toResourceReference();
        $junior   = self::revoke(self::user('junior'))->toResourceReference();
        $external = self::revoke(new Reference('external', '1'))->toResourceReference();
        $checks   = $this->checks(self::senior('admin'), self::unexpected(...));
        $unranked = $this->checks(self::user('unranked'), self::unexpected(...));
        $object   = $this->checks(new Subject(new \stdClass), self::unexpected(...));
        $roleless = self::revoke(StubTenant::query()->create(['id' => 'tenant-a', 'name' => 'tenant-a']))->toResourceReference();

        self::assertSame(DecisionReason::ADMINISTRATION_RANK, OperationConstraints::weigh($allowed, PackagePermissions::PERMISSION_REVOKE, $peer, $checks)->reason);
        self::assertSame(DecisionReason::ADMINISTRATION_RANK_UNCOMPARABLE, self::weigh(PackagePermissions::PERMISSION_REVOKE, $external, $checks)->reason);
        self::assertSame(DecisionReason::ADMINISTRATION_RANK, OperationConstraints::weigh($allowed, PackagePermissions::PERMISSION_REVOKE, $junior, $unranked)->reason);
        self::assertSame(DecisionReason::ADMINISTRATION_RANK_UNCOMPARABLE, OperationConstraints::weigh($allowed, PackagePermissions::PERMISSION_REVOKE, $junior, $object)->reason);
        self::assertSame(DecisionReason::ADMINISTRATION_RANK_UNCOMPARABLE, self::weigh(PackagePermissions::PERMISSION_REVOKE, $roleless, $checks)->reason);
        self::assertTrue(OperationConstraints::weigh($allowed, PackagePermissions::PERMISSION_REVOKE, $junior, $checks)->isAllowed());

        config(['authorization.rank.enabled' => false]);

        self::assertTrue(OperationConstraints::weigh($allowed, PackagePermissions::PERMISSION_REVOKE, $external, $unranked)->isAllowed());
    }

    /**
     * The actor is ranked in the grant's own tenant and application: a senior
     * role it holds only in another tenant, or only in another application,
     * never makes it senior there.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheActorIsRankedInTheGrantsOwnScope(): void
    {
        $tenant = new Reference('tenant', 'a');
        $actor  = self::user('admin');
        $user   = self::rankedUser('user', 5);
        $top    = Role::query()->create(['name' => 'top', 'rank' => 1]);

        GrantService::instance()?->grantRole($actor, $top, tenant: $tenant, application: 'admin');

        $checks = $this->checks($actor, self::unexpected(...));
        $edit   = Permission::query()->create(['name' => 'posts:edit']);
        $revoke = static fn (GrantScope $scope): ResourceReference => OperationResource::revoke(PackagePermissions::PERMISSION_REVOKE, $user, $edit, $scope)->toResourceReference();

        self::assertTrue(self::weigh(PackagePermissions::PERMISSION_REVOKE, $revoke(new GrantScope($tenant, 'admin')), $checks)->isAllowed());
        self::assertSame(DecisionReason::ADMINISTRATION_RANK, self::weigh(PackagePermissions::PERMISSION_REVOKE, $revoke(new GrantScope($tenant)), $checks)->reason);
        self::assertSame(DecisionReason::ADMINISTRATION_RANK, self::weigh(PackagePermissions::PERMISSION_REVOKE, $revoke(new GrantScope($tenant, 'billing')), $checks)->reason);
        self::assertSame(DecisionReason::ADMINISTRATION_RANK, self::weigh(PackagePermissions::PERMISSION_REVOKE, $revoke(new GrantScope(null, 'admin')), $checks)->reason);
    }

    /**
     * The grantee is ranked across the whole reach of the change: the most
     * senior rank it holds there counts, held in the grant's tenant, in any
     * application for a grant to every application, in a tenant below for a
     * grant reaching below, and in any tenant for a platform-wide grant; a role
     * held outside the reach, or one with no rank, never counts.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheGranteeIsRankedAcrossTheWholeReach(): void
    {
        [$parent, $child, $other] = [new Reference('tenant', 'parent'), new Reference('tenant', 'child'), new Reference('tenant', 'other')];

        $this->app?->instance(TenantTree::class, (new StubTenantTree)->put($child, $parent));

        $checks = $this->checks(self::senior('admin'), self::unexpected(...));
        $edit   = Permission::query()->create(['name' => 'posts:edit']);
        $rank   = static fn (StubIdentity $user, GrantScope $scope): ?DecisionReason => self::weigh(
            PackagePermissions::PERMISSION_REVOKE,
            OperationResource::revoke(PackagePermissions::PERMISSION_REVOKE, $user, $edit, $scope)->toResourceReference(),
            $checks,
        )->reason;

        $local = self::user('local');

        GrantService::instance()?->grantRole($local, Role::query()->create(['name' => 'local-top', 'rank' => 0]), tenant: $parent);
        GrantService::instance()?->grantRole($local, Role::query()->create(['name' => 'unranked']));

        self::assertSame(DecisionReason::ADMINISTRATION_RANK, $rank($local, new GrantScope($parent)));
        self::assertSame(DecisionReason::ADMINISTRATION_RANK, $rank($local, GrantScope::platform()));
        self::assertNull($rank($local, new GrantScope($other)));

        $app = self::user('app');

        GrantService::instance()?->grantRole($app, Role::query()->create(['name' => 'app-top', 'rank' => 0]), application: 'admin');

        self::assertSame(DecisionReason::ADMINISTRATION_RANK, $rank($app, GrantScope::platform()));
        self::assertSame(DecisionReason::ADMINISTRATION_RANK, $rank($app, new GrantScope(null, 'admin')));
        self::assertNull($rank($app, new GrantScope(null, 'billing')));

        $below = self::user('below');

        GrantService::instance()?->grantRole($below, Role::query()->create(['name' => 'child-top', 'rank' => 0]), tenant: $child, includeSubtree: false);

        self::assertSame(DecisionReason::ADMINISTRATION_RANK, $rank($below, new GrantScope($parent)));
        self::assertNull($rank($below, new GrantScope($parent, null, false)));
        self::assertNull($rank($below, new GrantScope($other)));

        $expired = self::user('expired');

        GrantService::instance()?->grantRole($expired, Role::query()->create(['name' => 'expired-top', 'rank' => 0]), Carbon::now()->addMinute());
        Carbon::setTestNow(Carbon::now()->addHour());

        self::assertNull($rank($expired, GrantScope::platform()));

        Carbon::setTestNow();
    }

    /**
     * A reach that cannot be read leaves the grantee's rank unknown, so the
     * change is refused as uncomparable.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReachThatCannotBeReadIsUncomparable(): void
    {
        $this->app?->instance(TenantTree::class, new FailingTenantTree(failing: ['a']));

        $checks = $this->checks(self::senior('admin'), self::unexpected(...));
        $edit   = Permission::query()->create(['name' => 'posts:edit']);
        $revoke = OperationResource::revoke(PackagePermissions::PERMISSION_REVOKE, self::user('user'), $edit, new GrantScope(new Reference('tenant', 'a')));

        self::assertSame(DecisionReason::ADMINISTRATION_RANK_UNCOMPARABLE, self::weigh(PackagePermissions::PERMISSION_REVOKE, $revoke->toResourceReference(), $checks)->reason);
    }

    /**
     * A role grant is weighed against the rank it would give the grantee, and a
     * role grant that only shortens one held is not; nor is a revocation of a
     * senior role the grantee does not hold.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARoleGrantIsWeighedAgainstTheRankItGives(): void
    {
        $allowed = Decision::allow(DecisionStage::ALLOW);
        $user    = self::user('user');
        $senior  = Role::query()->create(['name' => 'senior', 'rank' => 0]);
        $checks  = $this->checks(self::senior('admin'), static fn (): Decision => $allowed);
        $grant   = OperationResource::grant(PackagePermissions::ROLE_GRANT, $user, $senior, GrantScope::platform());

        self::assertSame(DecisionReason::ADMINISTRATION_RANK, self::weigh(PackagePermissions::ROLE_GRANT, $grant->toResourceReference(), $checks)->reason);

        $junior = Role::query()->create(['name' => 'junior', 'rank' => 9]);

        GrantService::instance()?->grantRole($user, $junior);

        $again = OperationResource::grant(PackagePermissions::ROLE_GRANT, $user, $junior, GrantScope::platform());

        self::assertTrue($again->isNarrowing);
        self::assertTrue(OperationConstraints::weigh($allowed, PackagePermissions::ROLE_GRANT, $again->toResourceReference(), $checks)->isAllowed());

        $revoke = OperationResource::revoke(PackagePermissions::ROLE_REVOKE, $user, $senior, GrantScope::platform());

        self::assertTrue(self::weigh(PackagePermissions::ROLE_REVOKE, $revoke->toResourceReference(), $checks)->isAllowed());
    }

    /**
     * A change to the actor itself is never weighed by rank; one that may widen
     * authority asks for `authorization:administration.self`, and is refused as
     * self without it, while one that only narrows asks nothing; once allowed
     * at its node, the self right is asked again across the change's reach.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChangeToTheActorItselfNeedsTheSelfRight(): void
    {
        $allowed = Decision::allow(DecisionStage::ALLOW);
        $admin   = self::user('admin');
        $grant   = OperationResource::grant(PackagePermissions::ROLE_GRANT, $admin, Role::query()->create(['name' => 'editor']), GrantScope::platform())->toResourceReference();
        $revoke  = self::revoke($admin)->toResourceReference();
        $denied  = Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT);
        $asked   = null;
        $refused = $this->checks($admin, static function (string $action, ?ResourceReference $on) use ($allowed, $denied, &$asked): Decision {
            if ($action === PackagePermissions::ADMINISTRATION_SELF) {
                $asked = $on;
            }

            return $action === PackagePermissions::ROLE_GRANT ? $allowed : $denied;
        });

        self::assertSame(DecisionReason::ADMINISTRATION_SELF, OperationConstraints::weigh($allowed, PackagePermissions::ROLE_GRANT, $grant, $refused)->reason);
        self::assertSame($grant, $asked);
        self::assertTrue(OperationConstraints::weigh($allowed, PackagePermissions::PERMISSION_REVOKE, $revoke, $refused)->isAllowed());
        self::assertSame([PackagePermissions::ROLE_GRANT, PackagePermissions::ADMINISTRATION_SELF], \array_column($this->asked, 0));

        $identity = $this->checks(new Subject(new \stdClass, $admin), static fn (): Decision => $allowed);

        self::assertTrue(OperationConstraints::weigh($allowed, PackagePermissions::ROLE_GRANT, $grant, $identity)->isAllowed());
        self::assertSame(
            [
                PackagePermissions::ROLE_GRANT,
                PackagePermissions::ADMINISTRATION_SELF,
                PackagePermissions::ROLE_GRANT,
                PackagePermissions::ADMINISTRATION_SELF,
                PackagePermissions::ADMINISTRATION_SELF,
            ],
            \array_column($this->asked, 0),
        );
    }

    /**
     * The self right is weighed across the change's whole reach, as its action
     * is (N79): an actor allowed `authorization:*` at the platform, but holding
     * a role in one tenant whose policy denies
     * `authorization:administration.self`, is refused a platform-wide grant to
     * itself as self, though the right is allowed at the node the grant is
     * decided at; with nothing to limit the right it is allowed, a grant in a
     * tenant the deny does not reach still is, and a change that only narrows
     * is never weighed by the self rule.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheSelfRightIsWeighedAcrossTheWholeReach(): void
    {
        [$admin, $check] = self::administrator();

        $write  = Permission::query()->create(['name' => 'comments:write']);
        $grant  = static fn (GrantScope $scope): Decision => $check(OperationResource::grant(PackagePermissions::PERMISSION_GRANT, $admin, $write, $scope));
        $revoke = OperationResource::revoke(PackagePermissions::PERMISSION_REVOKE, $admin, $write, GrantScope::platform());

        self::assertTrue($grant(GrantScope::platform())->isAllowed());

        self::restrictIn($admin, 't0', PackagePermissions::ADMINISTRATION_SELF);

        self::assertSame(DecisionReason::ADMINISTRATION_SELF, $grant(GrantScope::platform())->reason);
        self::assertSame(DecisionStage::ADMINISTRATION, $grant(GrantScope::platform())->stage);
        self::assertTrue($grant(new GrantScope(Reference::of(StubTenant::query()->create(['id' => 't1', 'name' => 't1'])), null, false))->isAllowed());
        self::assertTrue($check($revoke)->isAllowed());
    }

    /**
     * The unbounded right is weighed across the change's whole reach: a
     * platform-wide removal of a boundary is allowed while nothing limits
     * `authorization:administration.unbounded`, and refused as unprovable once
     * the actor holds a role in one tenant whose policy denies it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheUnboundedRightIsWeighedAcrossTheWholeReach(): void
    {
        [$admin, $check] = self::administrator();

        $cap    = Policy::create(['name' => 'cap', 'document' => ['statements' => [['effect' => 'allow', 'actions' => ['posts:read']]]]]);
        $remove = OperationResource::revoke(PackagePermissions::BOUNDARY_REMOVE, self::user('user'), $cap, GrantScope::platform());

        self::assertTrue($check($remove)->isAllowed());

        self::restrictIn($admin, 't0', PackagePermissions::ADMINISTRATION_UNBOUNDED);

        self::assertSame(DecisionReason::ADMINISTRATION_UNPROVABLE, $check($remove)->reason);
    }

    /**
     * The impersonated right is weighed across the whole reach of a change to a
     * subject that may widen authority: a platform-wide grant made while
     * impersonating is refused as impersonating once the actor holds a role in
     * one tenant whose policy denies
     * `authorization:administration.impersonated`, while a grant in a tenant
     * the deny does not reach, and a change that only narrows, decided at its
     * node alone, are still allowed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheImpersonatedRightIsWeighedAcrossAWideningChangesReach(): void
    {
        [$admin] = self::administrator();

        $user   = self::user('user');
        $edit   = Permission::query()->firstOrCreate(['name' => 'posts:edit']);
        $acting = ActingContext::for($admin)->impersonatedBy(new Reference('support', '9'));
        $grant  = static fn (GrantScope $scope): Decision => $acting->check(OperationResource::grant(PackagePermissions::PERMISSION_GRANT, $user, $edit, $scope));

        self::assertTrue($grant(GrantScope::platform())->isAllowed());

        self::restrictIn($admin, 't0', PackagePermissions::ADMINISTRATION_IMPERSONATED);

        self::assertSame(DecisionReason::ADMINISTRATION_IMPERSONATING, $grant(GrantScope::platform())->reason);
        self::assertTrue($grant(new GrantScope(Reference::of(StubTenant::query()->create(['id' => 't1', 'name' => 't1'])), null, false))->isAllowed());
        self::assertTrue($acting->check(self::revoke($user))->isAllowed());
    }

    /**
     * A direct grant of a permission is decided by possession: one the actor
     * neither holds nor may grant is refused as not grantable, as a role
     * carrying one is; a change to a subject no route proves, such as detaching
     * a denying policy, is refused as unprovable.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADirectPermissionGrantIsDecidedByPossession(): void
    {
        $allowed = Decision::allow(DecisionStage::ALLOW);
        $user    = self::user('user');
        $denied  = Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT);
        $refuse  = static fn (string $action): Decision => $action === PackagePermissions::PERMISSION_GRANTABLE ? $denied : $allowed;
        $checks  = $this->checks(self::senior('admin'), $refuse);

        $grant = self::permissionGrant($user)->toResourceReference();

        self::assertSame(DecisionReason::ADMINISTRATION_NOT_GRANTABLE, self::weigh(PackagePermissions::PERMISSION_GRANT, $grant, $checks)->reason);
        self::assertSame(DecisionReason::ADMINISTRATION_NOT_GRANTABLE, self::weigh(PackagePermissions::ROLE_GRANT, self::roleGrant()->toResourceReference(), $checks)->reason);
        self::assertSame(DecisionReason::ADMINISTRATION_UNPROVABLE, self::weigh(PackagePermissions::POLICY_DETACH, self::detach($user)->toResourceReference(), $checks)->reason);

        $granter = self::senior('granter');

        GrantService::instance()?->grantPermission($granter, Permission::query()->create(['name' => PackagePermissions::PERMISSION_GRANTABLE]));

        $grantable = $this->checks($granter, static fn (): Decision => $allowed);

        self::assertTrue(OperationConstraints::weigh($allowed, PackagePermissions::PERMISSION_GRANT, self::permissionGrant($user)->toResourceReference(), $grantable)->isAllowed());
    }

    /**
     * The constraints are weighed in order, the first that fails refusing: rank
     * before what the change hands out, and, for a change to the actor itself,
     * the self rule before it; an action whose record is of another kind than
     * the one it hands out is unprovable.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRankAndTheSelfRuleComeBeforeWhatTheChangeHandsOut(): void
    {
        $allowed = Decision::allow(DecisionStage::ALLOW);
        $denied  = Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT);
        $admin   = self::rankedUser('admin', 2);
        $refused = [PackagePermissions::PERMISSION_GRANTABLE, PackagePermissions::ADMINISTRATION_SELF];
        $refuse  = static fn (string $action): Decision => \in_array($action, $refused, true) ? $denied : $allowed;
        $checks  = $this->checks($admin, $refuse);
        $peer    = self::permissionGrant(self::rankedUser('peer', 2))->toResourceReference();
        $self    = self::permissionGrant($admin)->toResourceReference();

        self::assertSame(DecisionReason::ADMINISTRATION_RANK, self::weigh(PackagePermissions::PERMISSION_GRANT, $peer, $checks)->reason);
        self::assertSame(DecisionReason::ADMINISTRATION_SELF, self::weigh(PackagePermissions::PERMISSION_GRANT, $self, $checks)->reason);

        $senior     = $this->checks(self::senior('chief-admin'), static fn (): Decision => $allowed);
        $user       = self::user('user');
        $role       = OperationResource::grant(PackagePermissions::PERMISSION_GRANT, $user, Role::query()->create(['name' => 'empty']), GrantScope::platform());
        $permission = OperationResource::grant(PackagePermissions::POLICY_ATTACH, $user, Permission::query()->firstOrCreate(['name' => 'posts:edit']), GrantScope::platform());

        self::assertSame(DecisionReason::ADMINISTRATION_UNPROVABLE, self::weigh(PackagePermissions::PERMISSION_GRANT, $role->toResourceReference(), $senior)->reason);
        self::assertSame(DecisionReason::ADMINISTRATION_UNPROVABLE, self::weigh(PackagePermissions::POLICY_ATTACH, $permission->toResourceReference(), $senior)->reason);
    }

    /**
     * A change to a subject is weighed by what it hands out: a role whose chain
     * cannot be read is unprovable, a policy by the policy route, and a
     * boundary replaced by a wider one, or removed, only with
     * `administration.unbounded` on the same operation; a policy grantable
     * descriptor is never weighed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChangeToASubjectIsWeighedByWhatItHandsOut(): void
    {
        $allowed = Decision::allow(DecisionStage::ALLOW);
        $user    = self::user('user');
        $gone    = (new Role)->forceFill(['id' => '01a1b0c0-0000-7000-8000-00000000dead', 'name' => 'gone']);
        $cap     = Policy::create(['name' => 'cap', 'document' => ['statements' => [['effect' => 'allow', 'actions' => ['posts:read']]]]]);
        $remove  = OperationResource::revoke(PackagePermissions::BOUNDARY_REMOVE, $user, $cap, GrantScope::platform())->toResourceReference();
        $scoped  = Policy::create(['name' => 'scoped', 'document' => ['statements' => [['effect' => 'allow', 'actions' => ['posts:read'], 'resources' => ['posts:1']]]]]);
        $attach  = OperationResource::grant(PackagePermissions::POLICY_ATTACH, $user, $scoped, GrantScope::platform());
        $bounded = static fn (bool $unbounded): \Closure => static fn (string $action): Decision => $action !== PackagePermissions::ADMINISTRATION_UNBOUNDED || $unbounded
            ? $allowed
            : Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT);

        $role = OperationResource::grant(PackagePermissions::ROLE_GRANT, $user, $gone, GrantScope::platform())->toResourceReference();

        $admin = self::senior('admin');

        self::assertSame(DecisionReason::ADMINISTRATION_UNPROVABLE, self::weigh(PackagePermissions::ROLE_GRANT, $role, $this->checks($admin, $bounded(true)))->reason);
        $attaching = $attach->toResourceReference();

        self::assertSame(DecisionReason::ADMINISTRATION_UNPROVABLE, self::weigh(PackagePermissions::POLICY_ATTACH, $attaching, $this->checks($admin, $bounded(true)))->reason);
        self::assertSame(DecisionReason::ADMINISTRATION_UNPROVABLE, self::weigh(PackagePermissions::BOUNDARY_REMOVE, $remove, $this->checks($admin, $bounded(false)))->reason);
        self::assertSame(PackagePermissions::ADMINISTRATION_UNBOUNDED, \array_column($this->asked, 0)[\count($this->asked) - 1]);
        self::assertTrue(self::weigh(PackagePermissions::BOUNDARY_REMOVE, $remove, $this->checks($admin, $bounded(true)))->isAllowed());

        $descriptor = $attach->policyGrantable($scoped, 'abc')->toResourceReference();
        $asked      = \count($this->asked);

        self::assertSame($allowed, OperationConstraints::weigh($allowed, PackagePermissions::POLICY_GRANTABLE, $descriptor, $this->checks($admin, self::unexpected(...))));
        self::assertCount($asked, $this->asked);
    }

    /**
     * Through `check()`, the stage follows the allow: a subject holding every
     * action is refused the detach of a denying policy as unprovable and
     * allowed a revocation, a check of the action with no operation is allowed,
     * and a subject not holding the action is refused as the allow stage
     * refuses it, the stage never reached.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheStageFollowsTheAllowThroughCheck(): void
    {
        $admin = self::senior('admin');
        $other = self::user('other');

        $admin->givePermission(Permission::create(['name' => 'authorization:*']));

        $grant = Authorization::for($admin)->check(PackagePermissions::POLICY_DETACH, self::detach($other));

        self::assertSame(DecisionReason::ADMINISTRATION_UNPROVABLE, $grant->reason);
        self::assertSame(DecisionStage::ADMINISTRATION, $grant->stage);
        self::assertStringContainsString('[administration] administration.unprovable: refused', $grant->explain()->toText());
        self::assertTrue(Authorization::for($admin)->check(PackagePermissions::PERMISSION_REVOKE, self::revoke(self::user('user')))->isAllowed());
        self::assertTrue(Authorization::for($admin)->check(PackagePermissions::ROLE_GRANT)->isAllowed());
        self::assertSame(DecisionReason::NO_MATCH, ActingContext::for($other)->check(self::revoke(self::user('user')))->reason);
        self::assertSame(DecisionStage::IMPLICIT, ActingContext::for($other)->check(self::revoke(self::user('user')))->stage);
    }

    /**
     * Weigh an allowed decision of the action on the operation through the
     * stage.
     *
     * @param  string  $action
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference  $operation
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @return \SineMacula\Laravel\Authorization\Evaluation\Decision
     */
    private static function weigh(string $action, ResourceReference $operation, FurtherChecks $checks): Decision
    {
        return OperationConstraints::weigh(Decision::allow(DecisionStage::ALLOW), $action, $operation, $checks);
    }

    /**
     * Fail the test: no further check was expected.
     *
     * @return \SineMacula\Laravel\Authorization\Evaluation\Decision
     */
    private static function unexpected(): Decision
    {
        self::fail('No further check was expected.');
    }

    /**
     * Return further checks for the actor, deciding each check through the
     * callback and recording what was asked, in the scope in place.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject|\Tests\Feature\Stubs\StubIdentity  $actor
     * @param  \Closure(string, \SineMacula\Laravel\Authorization\Support\ResourceReference|null): \SineMacula\Laravel\Authorization\Evaluation\Decision  $decide
     * @return \SineMacula\Laravel\Authorization\Administration\FurtherChecks
     */
    private function checks(StubIdentity|Subject $actor, \Closure $decide): FurtherChecks
    {
        $record = function (string $action, ?ResourceReference $on) use ($decide): Decision {
            $this->asked[] = [$action, TenantScope::currentApplication(), TenantScope::isBelowTenant(), TenantScope::currentTenant()];

            return $decide($action, $on);
        };

        return new FurtherChecks($actor instanceof Subject ? $actor : new Subject($actor, $actor), $record, static fn (): CheckSources => self::noSources());
    }

    /**
     * Return a senior administrator allowed `authorization:*` and `*:*` at the
     * platform, and a callback deciding an operation as it.
     *
     * @return array{
     *     \Tests\Feature\Stubs\StubIdentity,
     *     \Closure(\SineMacula\Laravel\Authorization\Administration\OperationResource): \SineMacula\Laravel\Authorization\Evaluation\Decision
     * }
     *
     * @throws \Throwable
     */
    private static function administrator(): array
    {
        $admin = self::senior('admin');

        $admin->givePermission(Permission::query()->create(['name' => 'authorization:*']));
        $admin->givePermission(Permission::query()->create(['name' => '*:*']));

        return [$admin, static fn (OperationResource $operation): Decision => ActingContext::for($admin)->check($operation)];
    }

    /**
     * Grant the actor, in a new tenant with the id, a role carrying a policy
     * that denies the action.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $actor
     * @param  string  $tenant
     * @param  string  $action
     * @return void
     *
     * @throws \Throwable
     */
    private static function restrictIn(StubIdentity $actor, string $tenant, string $action): void
    {
        $denied = StubTenant::query()->create(['id' => $tenant, 'name' => $tenant]);
        $role   = Role::query()->create(['name' => 'restricted', 'rank' => 8]);
        $policy = Policy::create(['name' => 'restricting', 'document' => ['statements' => [['effect' => 'deny', 'actions' => [$action]]]]]);

        GrantService::instance()?->attachPolicy($role, $policy);
        GrantService::instance()?->grantRole($actor, $role, tenant: $denied);
    }

    /**
     * Return the identity with the id, created on first use.
     *
     * @param  string  $id
     * @return \Tests\Feature\Stubs\StubIdentity
     */
    private static function user(string $id): StubIdentity
    {
        return StubIdentity::query()->firstOrCreate(['id' => $id]);
    }

    /**
     * Return the identity with the id, holding the most senior rank.
     *
     * @param  string  $id
     * @return \Tests\Feature\Stubs\StubIdentity
     *
     * @throws \Throwable
     */
    private static function senior(string $id): StubIdentity
    {
        $user = self::user($id);

        GrantService::instance()?->grantRole($user, Role::query()->firstOrCreate(['name' => 'chief'], ['rank' => 1]));

        return $user;
    }

    /**
     * Return the identity with the id, holding a platform role of the rank.
     *
     * @param  string  $id
     * @param  int  $rank
     * @return \Tests\Feature\Stubs\StubIdentity
     *
     * @throws \Throwable
     */
    private static function rankedUser(string $id, int $rank): StubIdentity
    {
        $user = self::user($id);

        GrantService::instance()?->grantRole($user, Role::query()->firstOrCreate(['name' => 'rank-' . $rank], ['rank' => $rank]));

        return $user;
    }

    /**
     * Return a proposed grant of a role to a grantee.
     *
     * @return \SineMacula\Laravel\Authorization\Administration\OperationResource
     */
    private static function roleGrant(): OperationResource
    {
        $role = Role::query()->firstOrCreate(['name' => 'editor']);

        RoleService::instance()?->grantPermission($role, Permission::query()->firstOrCreate(['name' => 'posts:edit']));

        return OperationResource::grant(PackagePermissions::ROLE_GRANT, self::user('grantee'), $role, GrantScope::platform());
    }

    /**
     * Return a proposed detach of a denying policy from the grantee.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $grantee
     * @return \SineMacula\Laravel\Authorization\Administration\OperationResource
     */
    private static function detach(StubIdentity $grantee): OperationResource
    {
        return OperationResource::revoke(PackagePermissions::POLICY_DETACH, $grantee, self::denying(), GrantScope::platform());
    }

    /**
     * Return the policy that denies every post action, created on first use.
     *
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     */
    private static function denying(): Policy
    {
        $deny = ['effect' => 'deny', 'actions' => ['posts:*']];

        return Policy::query()->where('name', 'denying')->first() ?? Policy::create(['name' => 'denying', 'document' => ['statements' => [$deny]]]);
    }

    /**
     * Return a proposed direct grant of a permission to the grantee.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $grantee
     * @return \SineMacula\Laravel\Authorization\Administration\OperationResource
     */
    private static function permissionGrant(StubIdentity $grantee): OperationResource
    {
        return OperationResource::grant(PackagePermissions::PERMISSION_GRANT, $grantee, Permission::query()->firstOrCreate(['name' => 'posts:edit']), GrantScope::platform());
    }

    /**
     * Return a proposed revocation of a permission from the grantee.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @return \SineMacula\Laravel\Authorization\Administration\OperationResource
     */
    private static function revoke(Model|Reference $grantee): OperationResource
    {
        $permission = Permission::query()->firstOrCreate(['name' => 'posts:edit']);

        return OperationResource::revoke(PackagePermissions::PERMISSION_REVOKE, $grantee, $permission, GrantScope::platform());
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
