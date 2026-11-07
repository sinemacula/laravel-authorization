<?php

declare(strict_types = 1);

namespace Tests\Feature\Administration;

use Illuminate\Database\Eloquent\Model;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Administration\FurtherChecks;
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
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubTenant;
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
        $checks     = $this->checks(self::user('admin'), null, self::unexpected(...));

        self::assertSame($denied, OperationConstraints::weigh($denied, PackagePermissions::ROLE_GRANT, $operation, $checks));
        self::assertSame($allowed, OperationConstraints::weigh($allowed, PackagePermissions::ROLE_GRANT, null, $checks));
        self::assertSame($allowed, OperationConstraints::weigh($allowed, PackagePermissions::ROLE_GRANT, ResourceReference::record('post', '1'), $checks));
        self::assertSame($allowed, OperationConstraints::weigh($allowed, PackagePermissions::ROLE_REVOKE, $operation, $checks));
        self::assertSame($allowed, OperationConstraints::weigh($allowed, PackagePermissions::PERMISSION_GRANTABLE, $descriptor, $checks));
    }

    /**
     * An allowed operation on anything but a subject that may widen authority
     * is refused as unprovable at the administration stage, its trace ending
     * with the refusing constraint by its code after every step the allow took,
     * and its freshness kept; one that can only narrow passes, with one
     * satisfied step.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnOperationOnARoleIsRefusedUnlessItNarrows(): void
    {
        $step     = new TraceEntry(DecisionStage::ALLOW, TraceOutcome::HELD, permission: PackagePermissions::PERMISSION_GRANT);
        $fresh    = new RequirementFreshness('session-1');
        $allowed  = Decision::allow(DecisionStage::ALLOW, [], [$step])->withFreshness($fresh);
        $role     = Role::query()->create(['name' => 'editor']);
        $edit     = Permission::query()->create(['name' => 'posts:edit']);
        $checks   = $this->checks(self::user('admin'), null, self::unexpected(...));
        $grant    = OperationResource::grant(PackagePermissions::PERMISSION_GRANT, $role, $edit, GrantScope::platform());
        $revoke   = OperationResource::revoke(PackagePermissions::PERMISSION_REVOKE, $role, $edit, GrantScope::platform());
        $decision = OperationConstraints::weigh($allowed, PackagePermissions::PERMISSION_GRANT, $grant->toResourceReference(), $checks);

        self::assertFalse($decision->isAllowed());
        self::assertSame(DecisionReason::ADMINISTRATION_UNPROVABLE, $decision->reason);
        self::assertSame(DecisionStage::ADMINISTRATION, $decision->stage);
        self::assertSame([], $decision->statements);
        self::assertEquals([$step, new TraceEntry(DecisionStage::ADMINISTRATION, TraceOutcome::REFUSED, null, [], 'administration.unprovable')], $decision->trace);
        self::assertSame($fresh, $decision->freshness);

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
        $refusing = $this->checks(self::senior('admin'), null, static function (string $action, ?ResourceReference $on) use (&$resource): Decision {
            $resource = $on;

            return Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT);
        });

        self::assertSame(DecisionReason::ADMINISTRATION_IMPERSONATING, OperationConstraints::weigh($allowed, PackagePermissions::PERMISSION_REVOKE, $revoke, $refusing)->reason);
        self::assertSame(PackagePermissions::ADMINISTRATION_IMPERSONATED, $this->asked[0][0]);
        self::assertSame($revoke, $resource);

        $allowing = $this->checks(self::senior('admin'), null, static fn (): Decision => $allowed);

        self::assertTrue(OperationConstraints::weigh($allowed, PackagePermissions::PERMISSION_REVOKE, $revoke, $allowing)->isAllowed());
    }

    /**
     * A change to a grant row is made from the tenant that holds it, the
     * platform's from the platform, or refused as not the owner's before any
     * further check; a change that changes nothing edits nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOnlyTheOwnerChangesAGrantRow(): void
    {
        $allowed = Decision::allow(DecisionStage::ALLOW);
        $tenant  = new Reference('tenant', 'a');
        $user    = self::user('user');
        $admin   = self::senior('admin');
        $edit    = Permission::query()->create(['name' => 'posts:edit']);
        $revoke  = OperationResource::revoke(PackagePermissions::PERMISSION_REVOKE, $user, $edit, new GrantScope($tenant))->toResourceReference();
        $kept    = OperationResource::unchanged(PackagePermissions::PERMISSION_REVOKE, $user, null, new GrantScope($tenant))->toResourceReference();

        $platform = $this->checks($admin, null, self::unexpected(...));
        $other    = $this->checks($admin, new Reference('tenant', 'b'), self::unexpected(...));

        self::assertSame(DecisionReason::ADMINISTRATION_OWNER, self::weigh(PackagePermissions::PERMISSION_REVOKE, $revoke, $platform)->reason);
        self::assertSame(DecisionReason::ADMINISTRATION_OWNER, self::weigh(PackagePermissions::PERMISSION_REVOKE, $revoke, $other)->reason);
        self::assertTrue(OperationConstraints::weigh($allowed, PackagePermissions::PERMISSION_REVOKE, $revoke, $this->checks($admin, $tenant, self::unexpected(...)))->isAllowed());
        self::assertTrue(OperationConstraints::weigh($allowed, PackagePermissions::PERMISSION_REVOKE, $kept, $this->checks($admin, null, self::unexpected(...)))->isAllowed());
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
        $denying  = $this->checks(self::senior('admin'), $tenant, static fn (): Decision => Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT));

        self::assertSame(DecisionReason::ADMINISTRATION_SCOPE, self::weigh(PackagePermissions::POLICY_ATTACH, $grant->toResourceReference(), $denying)->reason);
        self::assertSame([PackagePermissions::POLICY_ATTACH, 'admin', true, ['tenant', 'a']], $this->asked[0]);

        $allowing = $this->checks(self::senior('admin'), $tenant, static fn (): Decision => $allowed);

        self::assertSame(DecisionReason::ADMINISTRATION_UNPROVABLE, self::weigh(PackagePermissions::POLICY_ATTACH, $node->toResourceReference(), $allowing)->reason);
        self::assertSame([PackagePermissions::POLICY_ATTACH, null, false, ['tenant', 'a']], $this->asked[1]);

        $platformChecks = $this->checks(self::senior('admin'), null, static fn (): Decision => $allowed);

        OperationConstraints::weigh($allowed, PackagePermissions::POLICY_ATTACH, $platform->toResourceReference(), $platformChecks);

        self::assertSame([PackagePermissions::POLICY_ATTACH, null, false, null], $this->asked[2]);
        self::assertCount(3, $this->asked);
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
        $checks   = $this->checks(self::senior('admin'), null, self::unexpected(...));
        $unranked = $this->checks(self::user('unranked'), null, self::unexpected(...));
        $object   = $this->checks(new Subject(new \stdClass), null, self::unexpected(...));
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
     * Rank is compared in the grant's own scope: a role the grantee holds in
     * another tenant never counts.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRankIsComparedInTheGrantsScope(): void
    {
        $allowed = Decision::allow(DecisionStage::ALLOW);
        $tenant  = new Reference('tenant', 'a');
        $user    = self::user('user');
        $checks  = $this->checks(self::senior('admin'), $tenant, self::unexpected(...));

        GrantService::instance()?->grantRole($user, Role::query()->create(['name' => 'elsewhere', 'rank' => 0]), tenant: new Reference('tenant', 'b'));

        $revoke = OperationResource::revoke(PackagePermissions::PERMISSION_REVOKE, $user, Permission::query()->create(['name' => 'posts:edit']), new GrantScope($tenant));

        self::assertTrue(OperationConstraints::weigh($allowed, PackagePermissions::PERMISSION_REVOKE, $revoke->toResourceReference(), $checks)->isAllowed());
    }

    /**
     * A role grant is weighed against the rank it would give the grantee, and a
     * role grant that only shortens one held is not.
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
        $checks  = $this->checks(self::senior('admin'), null, static fn (): Decision => $allowed);
        $grant   = OperationResource::grant(PackagePermissions::ROLE_GRANT, $user, $senior, GrantScope::platform());

        self::assertSame(DecisionReason::ADMINISTRATION_RANK, self::weigh(PackagePermissions::ROLE_GRANT, $grant->toResourceReference(), $checks)->reason);

        $junior = Role::query()->create(['name' => 'junior', 'rank' => 9]);

        GrantService::instance()?->grantRole($user, $junior);

        $again = OperationResource::grant(PackagePermissions::ROLE_GRANT, $user, $junior, GrantScope::platform());

        self::assertTrue($again->isNarrowing);
        self::assertTrue(OperationConstraints::weigh($allowed, PackagePermissions::ROLE_GRANT, $again->toResourceReference(), $checks)->isAllowed());
    }

    /**
     * A change to the actor itself is never weighed by rank; one that may widen
     * authority asks for `authorization:administration.self`, and is refused as
     * self without it, while one that only narrows asks nothing.
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
        $refused = $this->checks($admin, null, static fn (string $action): Decision => $action === PackagePermissions::ROLE_GRANT ? $allowed : $denied);

        self::assertSame(DecisionReason::ADMINISTRATION_SELF, OperationConstraints::weigh($allowed, PackagePermissions::ROLE_GRANT, $grant, $refused)->reason);
        self::assertTrue(OperationConstraints::weigh($allowed, PackagePermissions::PERMISSION_REVOKE, $revoke, $refused)->isAllowed());
        self::assertSame([PackagePermissions::ROLE_GRANT, PackagePermissions::ADMINISTRATION_SELF], \array_column($this->asked, 0));

        $identity = $this->checks(new Subject(new \stdClass, $admin), null, static fn (): Decision => $allowed);

        self::assertSame(DecisionReason::ADMINISTRATION_UNPROVABLE, OperationConstraints::weigh($allowed, PackagePermissions::ROLE_GRANT, $grant, $identity)->reason);
        self::assertSame(
            [PackagePermissions::ROLE_GRANT, PackagePermissions::ADMINISTRATION_SELF, PackagePermissions::ROLE_GRANT, PackagePermissions::ADMINISTRATION_SELF],
            \array_column($this->asked, 0),
        );
    }

    /**
     * A direct grant of a permission is decided by possession: one the actor
     * neither holds nor may grant is refused as not grantable; any other grant
     * to a subject that may widen authority is refused as unprovable.
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
        $checks  = $this->checks(self::senior('admin'), null, $refuse);

        $grant = self::permissionGrant($user)->toResourceReference();

        self::assertSame(DecisionReason::ADMINISTRATION_NOT_GRANTABLE, self::weigh(PackagePermissions::PERMISSION_GRANT, $grant, $checks)->reason);
        self::assertSame(DecisionReason::ADMINISTRATION_UNPROVABLE, self::weigh(PackagePermissions::ROLE_GRANT, self::roleGrant()->toResourceReference(), $checks)->reason);

        $grantable = $this->checks(self::senior('granter'), null, static fn (): Decision => $allowed);

        self::assertTrue(OperationConstraints::weigh($allowed, PackagePermissions::PERMISSION_GRANT, self::permissionGrant($user)->toResourceReference(), $grantable)->isAllowed());
    }

    /**
     * Through `check()`, the stage follows the allow: a subject holding every
     * action is refused a role grant as unprovable and allowed a revocation, a
     * check of the action with no operation is allowed, and a subject not
     * holding the action is refused as the allow stage refuses it, the stage
     * never reached.
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

        $grant = Authorization::for($admin)->check(PackagePermissions::ROLE_GRANT, self::roleGrant());

        self::assertSame(DecisionReason::ADMINISTRATION_UNPROVABLE, $grant->reason);
        self::assertSame(DecisionStage::ADMINISTRATION, $grant->stage);
        self::assertStringContainsString('[administration] administration.unprovable: refused', $grant->explain());
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
     * Return further checks for the actor, made from the origin, deciding each
     * check through the callback and recording what was asked, in the scope in
     * place.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject|\Tests\Feature\Stubs\StubIdentity  $actor
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $origin
     * @param  \Closure(string, \SineMacula\Laravel\Authorization\Support\ResourceReference|null): \SineMacula\Laravel\Authorization\Evaluation\Decision  $decide
     * @return \SineMacula\Laravel\Authorization\Administration\FurtherChecks
     */
    private function checks(StubIdentity|Subject $actor, ?Reference $origin, \Closure $decide): FurtherChecks
    {
        $record = function (string $action, ?ResourceReference $on) use ($decide): Decision {
            $this->asked[] = [$action, TenantScope::currentApplication(), TenantScope::isBelowTenant(), TenantScope::currentTenant()];

            return $decide($action, $on);
        };

        return new FurtherChecks($actor instanceof Subject ? $actor : new Subject($actor, $actor), $origin, $record, static fn (): null => null);
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
     * Return a proposed grant of a role to a grantee.
     *
     * @return \SineMacula\Laravel\Authorization\Administration\OperationResource
     */
    private static function roleGrant(): OperationResource
    {
        return OperationResource::grant(PackagePermissions::ROLE_GRANT, self::user('grantee'), Role::query()->firstOrCreate(['name' => 'editor']), GrantScope::platform());
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
}
