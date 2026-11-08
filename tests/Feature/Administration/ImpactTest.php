<?php

declare(strict_types = 1);

namespace Tests\Feature\Administration;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Administration\FurtherChecks;
use SineMacula\Laravel\Authorization\Administration\Impact;
use SineMacula\Laravel\Authorization\Administration\OperationResource;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Evaluation\CheckContext;
use SineMacula\Laravel\Authorization\Evaluation\CheckSources;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\SessionCaps;
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
use Tests\Fixtures\BulkChecks\FailingTenantTree;
use Tests\TestCase;

/**
 * Feature tests for `Impact`: a change to a shared definition weighed against
 * every holder it reaches at once.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Impact::class)]
final class ImpactTest extends TestCase
{
    /** @var list<array{string, array{0: string, 1: string}|null, bool}> Each further check asked: its action, the tenant and whether it stood below it. */
    private array $asked = [];

    /**
     * A set over its limit cannot be weighed, and a change reaching no holder
     * widens no one, so neither asks anything.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABoundlessOrEmptySetAsksNothing(): void
    {
        $checks = $this->checks(self::user('admin', 1), static fn (): Decision => self::fail('Nothing was to be asked.'));

        self::assertSame(DecisionReason::ADMINISTRATION_UNPROVABLE, Impact::refusal(self::operation(), self::resource(), Impact::reachOf(null), null, $checks));
        self::assertNull(Impact::refusal(self::operation(), self::resource(), Impact::reachOf(null), [], $checks));
    }

    /**
     * The operation's action is decided again across the whole reach, standing
     * below the owner's tenant, in every application, and refused as out of
     * scope when it is not allowed there, or when the actor is denied it in a
     * tenant the reach holds.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheActionIsDecidedAcrossTheWholeReach(): void
    {
        $tenant  = new Reference('tenant', 'a');
        $holders = [Reference::of(self::user('user'))];
        $denying = $this->checks(self::user('admin', 1), static fn (): Decision => Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT));

        self::assertSame(DecisionReason::ADMINISTRATION_SCOPE, Impact::refusal(self::operation(), self::resource(), Impact::reachOf($tenant), $holders, $denying));
        self::assertSame([[PackagePermissions::PERMISSION_GRANT, ['tenant', 'a'], true]], $this->asked);

        $allowing = $this->checks(self::user('admin', 1), static fn (): Decision => Decision::allow(DecisionStage::ALLOW));

        self::assertNull(Impact::refusal(self::operation(), self::resource(), Impact::reachOf(null), $holders, $allowing));
        self::assertSame([[PackagePermissions::PERMISSION_GRANT, null, false]], \array_slice($this->asked(), 1));
        self::assertEquals(new GrantScope($tenant, null, true), Impact::reachOf($tenant));

        $restricted = Role::query()->create(['name' => 'restricted']);
        $deny       = ['effect' => 'deny', 'actions' => [PackagePermissions::PERMISSION_GRANT]];

        self::grants()->attachPolicy($restricted, Policy::create(['name' => 'restricting', 'document' => ['statements' => [$deny]]]));
        self::grants()->grantRole(self::user('admin'), $restricted, tenant: $tenant);

        self::assertSame(DecisionReason::ADMINISTRATION_SCOPE, Impact::refusal(self::operation(), self::resource(), Impact::reachOf(null), $holders, $allowing));
    }

    /**
     * The actor must be strictly senior to every holder but itself anywhere the
     * reach goes, and to a rank the change gives them; a holder or an actor
     * whose rank cannot be read cannot be compared, and a reach whose tenants
     * cannot be read is refused by the scope rule before rank is weighed; with
     * rank turned off, rank stands in nobody's way.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheActorMustOutrankEveryHolder(): void
    {
        $actor   = self::user('admin', 2);
        $allowed = static fn (): Decision => Decision::allow(DecisionStage::ALLOW);
        $checks  = $this->checks($actor, $allowed);
        $reach   = Impact::reachOf(null);
        $refuse  = static fn (array $holders, ?int $granted = null): ?DecisionReason => Impact::refusal(self::operation(), self::resource(), $reach, $holders, $checks, $granted);
        $junior  = Reference::of(self::user('junior', 5));
        $peer    = Reference::of(self::user('peer', 2));

        self::grants()->grantRole(self::user('elsewhere'), self::rank(1), tenant: new Reference('tenant', 'a'));

        self::assertNull($refuse([$junior, Reference::of(self::user('unranked'))]));
        self::assertSame(DecisionReason::ADMINISTRATION_RANK, $refuse([$junior, $peer]));
        self::assertSame(DecisionReason::ADMINISTRATION_RANK, $refuse([$junior], 2));
        self::assertNull($refuse([$junior], 3));
        self::assertSame(DecisionReason::ADMINISTRATION_RANK, $refuse([Reference::of(self::user('elsewhere'))]));
        self::assertSame(DecisionReason::ADMINISTRATION_RANK_UNCOMPARABLE, $refuse([$junior, new Reference('external', '1')]));
        $unranked = $this->checks(self::user('unranked-admin'), $allowed);
        $unread   = $this->checks(new Subject(new \stdClass), $allowed);

        self::assertSame(DecisionReason::ADMINISTRATION_RANK, Impact::refusal(self::operation(), self::resource(), $reach, [$junior], $unranked));
        self::assertSame(DecisionReason::ADMINISTRATION_RANK_UNCOMPARABLE, Impact::refusal(self::operation(), self::resource(), $reach, [$junior], $unread));

        $this->app?->instance(TenantTree::class, new FailingTenantTree(failing: ['a']));

        $unreadable = Impact::reachOf(new Reference('tenant', 'a'));

        self::assertSame(DecisionReason::ADMINISTRATION_SCOPE, Impact::refusal(self::operation(), self::resource(), $unreadable, [$junior], $checks));

        config(['authorization.rank.enabled' => false]);

        self::assertNull($refuse([$junior, $peer, new Reference('external', '1')]));
    }

    /**
     * A change reaching the actor itself, its principal or its identity, is not
     * weighed by rank but needs `administration.self`, decided on the same
     * operation.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChangeReachingTheActorNeedsTheSelfRight(): void
    {
        $actor    = self::user('admin', 2);
        $holders  = [Reference::of($actor), Reference::of(self::user('junior', 5))];
        $resource = self::resource();
        $on       = null;
        $refusing = $this->checks($actor, static function (string $action, ?ResourceReference $resource) use (&$on): Decision {
            if ($action !== PackagePermissions::ADMINISTRATION_SELF) {
                return Decision::allow(DecisionStage::ALLOW);
            }

            $on = $resource;

            return Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT);
        });

        self::assertSame(DecisionReason::ADMINISTRATION_SELF, Impact::refusal(self::operation(), $resource, Impact::reachOf(null), $holders, $refusing));
        self::assertSame($resource, $on);
        $allowing = $this->checks($actor, static fn (): Decision => Decision::allow(DecisionStage::ALLOW));

        self::assertNull(Impact::refusal(self::operation(), $resource, Impact::reachOf(null), $holders, $allowing));
    }

    /**
     * The rules are weighed in order, the first that fails refusing: the scope
     * before rank, and rank before the self rule.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheScopeThenRankThenTheSelfRuleRefuse(): void
    {
        $actor   = self::user('admin', 2);
        $holders = [Reference::of($actor), Reference::of(self::user('peer', 2))];
        $denying = $this->checks($actor, static fn (): Decision => Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT));
        $noSelf  = $this->checks($actor, static fn (string $action): Decision => $action === PackagePermissions::ADMINISTRATION_SELF
            ? Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT)
            : Decision::allow(DecisionStage::ALLOW));

        self::assertSame(DecisionReason::ADMINISTRATION_SCOPE, Impact::refusal(self::operation(), self::resource(), Impact::reachOf(null), $holders, $denying));
        self::assertSame(DecisionReason::ADMINISTRATION_RANK, Impact::refusal(self::operation(), self::resource(), Impact::reachOf(null), $holders, $noSelf));
        self::assertSame(DecisionReason::ADMINISTRATION_SELF, Impact::refusal(self::operation(), self::resource(), Impact::reachOf(null), [Reference::of($actor)], $noSelf));
    }

    /**
     * A role is created or ranked only junior to the actor in the operation's
     * tenant: an equal or more senior rank is refused, an unranked actor ranks
     * no role, an actor whose rank cannot be read cannot be compared, and an
     * unranked role, or rank turned off, stands in nobody's way.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARankMustBeJuniorToTheActors(): void
    {
        $allowed   = static fn (): Decision => Decision::allow(DecisionStage::ALLOW);
        $checks    = $this->checks(self::user('admin', 2), $allowed);
        $operation = OperationResource::definition(PackagePermissions::ROLE_CREATE, new Role, ['rank' => 1]);

        self::assertNull(Impact::juniorRank($operation, 3, $checks));
        self::assertSame(DecisionReason::ADMINISTRATION_RANK, Impact::juniorRank($operation, 2, $checks));
        self::assertSame(DecisionReason::ADMINISTRATION_RANK, Impact::juniorRank($operation, 1, $checks));
        self::assertNull(Impact::juniorRank($operation, null, $checks));
        self::assertSame(DecisionReason::ADMINISTRATION_RANK, Impact::juniorRank($operation, 9, $this->checks(self::user('unranked'), $allowed)));
        self::assertSame(DecisionReason::ADMINISTRATION_RANK_UNCOMPARABLE, Impact::juniorRank($operation, 9, $this->checks(new Subject(new \stdClass), $allowed)));

        config(['authorization.rank.enabled' => false]);

        self::assertNull(Impact::juniorRank($operation, 1, $checks));
    }

    /**
     * Return the further checks asked so far.
     *
     * @return list<array{string, array{0: string, 1: string}|null, bool}>
     */
    private function asked(): array
    {
        return $this->asked;
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
            $this->asked[] = [$action, TenantScope::currentTenant(), TenantScope::isBelowTenant()];

            return $decide($action, $on);
        };

        return new FurtherChecks($actor instanceof Subject ? $actor : new Subject($actor, $actor), $record, static fn (): CheckSources => self::noSources());
    }

    /**
     * Return a proposed grant of a permission to a platform role.
     *
     * @return \SineMacula\Laravel\Authorization\Administration\OperationResource
     */
    private static function operation(): OperationResource
    {
        $role = Role::query()->firstOrCreate(['name' => 'editor']);

        return OperationResource::grant(PackagePermissions::PERMISSION_GRANT, $role, Permission::query()->firstOrCreate(['name' => 'posts:edit']), GrantScope::platform());
    }

    /**
     * Return the reference to the proposed operation.
     *
     * @return \SineMacula\Laravel\Authorization\Support\ResourceReference
     */
    private static function resource(): ResourceReference
    {
        return self::operation()->toResourceReference();
    }

    /**
     * Return the identity with the id, created on first use, holding a platform
     * role of the rank, or none for null.
     *
     * @param  string  $id
     * @param  int|null  $rank
     * @return \Tests\Feature\Stubs\StubIdentity
     *
     * @throws \Throwable
     */
    private static function user(string $id, ?int $rank = null): StubIdentity
    {
        $user = StubIdentity::query()->firstOrCreate(['id' => $id]);

        if ($rank !== null) {
            self::grants()->grantRole($user, self::rank($rank));
        }

        return $user;
    }

    /**
     * Return the platform role of the rank, created on first use.
     *
     * @param  int  $rank
     * @return \SineMacula\Laravel\Authorization\Models\Role
     */
    private static function rank(int $rank): Role
    {
        return Role::query()->firstOrCreate(['name' => 'rank-' . $rank], ['rank' => $rank]);
    }

    /**
     * Return the grant service.
     *
     * @return \SineMacula\Laravel\Authorization\Services\GrantService
     */
    private static function grants(): GrantService
    {
        return app(GrantService::class);
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
