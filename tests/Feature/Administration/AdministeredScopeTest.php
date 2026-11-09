<?php

declare(strict_types = 1);

namespace Tests\Feature\Administration;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Administration\AdministeredScope;
use SineMacula\Laravel\Authorization\Administration\FurtherChecks;
use SineMacula\Laravel\Authorization\Administration\OperationResource;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Enums\GrantOutcome;
use SineMacula\Laravel\Authorization\Evaluation\CheckContext;
use SineMacula\Laravel\Authorization\Evaluation\CheckSources;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
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
use Tests\Concerns\ActsAsAdministrator;
use Tests\Concerns\ActsAsTenant;
use Tests\Concerns\AssertsDelegatedRefusals;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubTenantTree;
use Tests\TestCase;

/**
 * Feature tests for `AdministeredScope`, the administered-scope rule (N79): an
 * actor must administer the whole reach of a change that may widen authority.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(AdministeredScope::class)]
final class AdministeredScopeTest extends TestCase
{
    use ActsAsAdministrator, ActsAsTenant, AssertsDelegatedRefusals;

    /** @var list<array{string, string, string|null, bool, array{string, string}|null}> Each further check or source asked: its kind, action, application, whether below, and the tenant in place. */
    private array $asked = [];

    /**
     * An actor allowed `authorization:*` at the platform, but holding a role in
     * one tenant that carries a policy denying `authorization:role.grant`, does
     * not administer a platform-wide grant, which reaches that tenant, so the
     * grant is refused as out of scope and writes nothing, while a grant in a
     * tenant the deny does not reach is made.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPlatformGrantIsRefusedWhereTheActionIsDeniedInATenant(): void
    {
        $actor  = self::administrator();
        $denied = self::createTenant('t0');
        $other  = self::createTenant('t1');
        $user   = StubIdentity::query()->create(['id' => 'u1']);
        $named  = Role::query()->create(['name' => 'named', 'rank' => 8]);

        self::grants()->grantRole(self::actorModel(), self::denyingRole(PackagePermissions::ROLE_GRANT), tenant: $denied);

        self::assertDelegatedRefusal(DecisionReason::ADMINISTRATION_SCOPE, static fn (): mixed => self::grants()->grantRole($user, $named, actor: $actor));
        self::assertSame(GrantOutcome::GRANTED, self::grants()->grantRole($user, $named, actor: $actor, tenant: $other));
    }

    /**
     * An actor administering a parent tenant's subtree, but holding a role in a
     * child that carries a policy denying `authorization:role.grant`, does not
     * administer a subtree grant from the parent, which reaches the child, so
     * it is refused as out of scope and writes nothing; a node-only grant in
     * the parent, which reaches no child, is made.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASubtreeGrantFromAParentIsRefusedWhereTheActionIsDeniedInAChild(): void
    {
        [$parent, $child] = $this->tree();

        $actor = self::administrator([]);
        $user  = StubIdentity::query()->create(['id' => 'u1']);
        $named = Role::query()->create(['name' => 'named', 'rank' => 8]);

        self::grants()->grantPermission(self::actorModel(), Permission::query()->firstOrCreate(['name' => 'authorization:*']), tenant: $parent);
        self::grants()->grantRole(self::actorModel(), self::denyingRole(PackagePermissions::ROLE_GRANT), tenant: $child);

        $this->actAsTenant($parent);

        self::assertDelegatedRefusal(DecisionReason::ADMINISTRATION_SCOPE, static fn (): mixed => self::grants()->grantRole($user, $named, actor: $actor, tenant: $parent));
        self::assertSame(GrantOutcome::GRANTED, self::grants()->grantRole($user, $named, actor: $actor, tenant: $parent, includeSubtree: false));
    }

    /**
     * A reach of one tenant's node alone is decided there, in its application,
     * never below it, and nothing more is read, since its decision reads all
     * that applies there: allowed, it is administered; denied, it is not.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testANodeReachIsDecidedAtItsNodeAlone(): void
    {
        $node = new GrantScope(new Reference('tenant', 'a'), 'admin', false);

        self::assertNull(self::refusal($node, $this->checks(true, null)));
        self::assertSame(DecisionReason::ADMINISTRATION_SCOPE, self::refusal($node, $this->checks(false, null)));
        self::assertSame([
            ['decide', PackagePermissions::ROLE_GRANT, 'admin', false, ['tenant', 'a']],
            ['decide', PackagePermissions::ROLE_GRANT, 'admin', false, ['tenant', 'a']],
        ], $this->asked);
    }

    /**
     * A reach wider than its node, a platform-wide one with or without the
     * tenants below, or a tenant's subtree, is decided at the platform or just
     * below the tenant, and the sources of the action are read there: with
     * nothing to limit it, it is administered; with sources that cannot be
     * read, or an action not allowed, it is not.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAWiderReachIsAdministeredOnlyWhenNothingCouldLimitIt(): void
    {
        $subtree = new GrantScope(new Reference('tenant', 'a'), 'admin');
        $node    = new GrantScope(null, null, false);

        self::assertNull(self::refusal(GrantScope::platform(), $this->checks(true, self::sources())));
        self::assertNull(self::refusal($subtree, $this->checks(true, self::sources())));
        self::assertSame([
            ['decide', PackagePermissions::ROLE_GRANT, null, false, null],
            ['sources', PackagePermissions::ROLE_GRANT, null, false, null],
            ['decide', PackagePermissions::ROLE_GRANT, 'admin', true, ['tenant', 'a']],
            ['sources', PackagePermissions::ROLE_GRANT, 'admin', true, ['tenant', 'a']],
        ], $this->asked);

        self::assertSame(DecisionReason::ADMINISTRATION_SCOPE, self::refusal(GrantScope::platform(), $this->checks(true, null)));
        self::assertSame(DecisionReason::ADMINISTRATION_SCOPE, self::refusal($node, $this->checks(true, null)));
        self::assertSame(DecisionReason::ADMINISTRATION_SCOPE, self::refusal($subtree, $this->checks(true, null)));
        self::assertSame(DecisionReason::ADMINISTRATION_SCOPE, self::refusal(GrantScope::platform(), $this->checks(false, self::sources())));
    }

    /**
     * Anything among the sources that could limit the action anywhere in a
     * wider reach refuses it: a deny naming it, a conditional one included, a
     * boundary not allowing it whole, and a session cap not covering it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWhatCouldLimitTheActionInTheReachRefusesIt(): void
    {
        $deny        = ['effect' => 'deny', 'actions' => ['authorization:role.*']];
        $conditional = [...$deny, 'conditions' => ['eq' => ['resource.application' => 'never']]];
        $narrow      = ['effect' => 'allow', 'actions' => ['authorization:role.revoke']];

        self::assertSame(DecisionReason::ADMINISTRATION_SCOPE, self::refusal(GrantScope::platform(), $this->checks(true, self::sources(policies: [$deny]))));
        self::assertSame(DecisionReason::ADMINISTRATION_SCOPE, self::refusal(GrantScope::platform(), $this->checks(true, self::sources(policies: [$conditional]))));
        self::assertSame(DecisionReason::ADMINISTRATION_SCOPE, self::refusal(GrantScope::platform(), $this->checks(true, self::sources(boundaries: [$narrow]))));
        self::assertSame(DecisionReason::ADMINISTRATION_SCOPE, self::refusal(GrantScope::platform(), $this->checks(true, self::sources(caps: ['authorization:role.revoke']))));
        self::assertNull(self::refusal(GrantScope::platform(), $this->checks(true, self::sources(caps: ['authorization:*']))));
    }

    /**
     * Any action is weighed across a reach by the same rule, on the resource
     * given, as an access review is admitted: decided just below the reach's
     * tenant, with its sources read there; allowed with nothing to limit it,
     * refused as out of scope when it is denied or limited; a node alone is
     * decided there.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnyActionIsWeighedAcrossItsReachOnTheResourceGiven(): void
    {
        $resource = ResourceReference::record('authorization:review', 'holders');
        $reach    = new GrantScope(new Reference('tenant', 'a'), 'admin');
        $actor    = StubIdentity::query()->firstOrCreate(['id' => 'admin']);
        $asked    = [];

        $checks = static function (bool $allowed, ?CheckSources $sources) use ($actor, $resource, &$asked): FurtherChecks {
            $decide = static function (string $action, ?ResourceReference $on) use ($allowed, $resource, &$asked): Decision {
                $asked[] = [$action, $on === $resource, TenantScope::currentApplication(), TenantScope::isBelowTenant(), TenantScope::currentTenant()];

                return $allowed ? Decision::allow(DecisionStage::ALLOW) : Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT);
            };

            return new FurtherChecks(new Subject($actor, $actor), $decide, static fn (string $action): ?CheckSources => $sources);
        };

        $denying = self::sources(policies: [['effect' => 'deny', 'actions' => ['authorization:review.*']]]);

        self::assertNull(AdministeredScope::refusalOf(PackagePermissions::REVIEW_READ, $resource, $reach, $checks(true, self::sources())));
        self::assertSame([[PackagePermissions::REVIEW_READ, true, 'admin', true, ['tenant', 'a']]], $asked);
        self::assertSame(DecisionReason::ADMINISTRATION_SCOPE, AdministeredScope::refusalOf(PackagePermissions::REVIEW_READ, $resource, $reach, $checks(false, self::sources())));
        self::assertSame(DecisionReason::ADMINISTRATION_SCOPE, AdministeredScope::refusalOf(PackagePermissions::REVIEW_READ, $resource, $reach, $checks(true, $denying)));
        self::assertNull(AdministeredScope::refusalOf(PackagePermissions::REVIEW_READ, $resource, new GrantScope(new Reference('tenant', 'a'), null, false), $checks(true, null)));
    }

    /**
     * A node's reach across every application is wider than the node, as a
     * subtree is: what could limit the action in any application refuses it,
     * and sources that cannot be read do too, while the same node in one
     * application, or in none, is decided at the node alone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testANodeAcrossApplicationsIsWeighedAsAWiderReach(): void
    {
        $resource = ResourceReference::record('authorization:review', 'holders');
        $node     = new GrantScope(new Reference('tenant', 'a'), null, false);
        $actor    = StubIdentity::query()->firstOrCreate(['id' => 'admin']);
        $checks   = static fn (?CheckSources $sources): FurtherChecks => new FurtherChecks(
            new Subject($actor, $actor),
            static fn (): Decision => Decision::allow(DecisionStage::ALLOW),
            static fn (): ?CheckSources => $sources,
        );

        $denying = self::sources(policies: [['effect' => 'deny', 'actions' => ['authorization:review.*']]]);

        self::assertNull(AdministeredScope::refusalOf(PackagePermissions::REVIEW_READ, $resource, $node, $checks($denying)));
        self::assertNull(AdministeredScope::refusalOf(PackagePermissions::REVIEW_READ, $resource, $node, $checks(null), false));
        self::assertSame(DecisionReason::ADMINISTRATION_SCOPE, AdministeredScope::refusalOf(PackagePermissions::REVIEW_READ, $resource, $node, $checks($denying), true));
        self::assertSame(DecisionReason::ADMINISTRATION_SCOPE, AdministeredScope::refusalOf(PackagePermissions::REVIEW_READ, $resource, $node, $checks(null), true));
        self::assertNull(AdministeredScope::refusalOf(PackagePermissions::REVIEW_READ, $resource, $node, $checks(self::sources()), true));
    }

    /**
     * Return why the role grant, decided across the reach through the checks,
     * is refused.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\GrantScope  $reach
     * @param  \SineMacula\Laravel\Authorization\Administration\FurtherChecks  $checks
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null
     */
    private static function refusal(GrantScope $reach, FurtherChecks $checks): ?DecisionReason
    {
        $role      = Role::query()->firstOrCreate(['name' => 'named']);
        $operation = OperationResource::grant(PackagePermissions::ROLE_GRANT, StubIdentity::query()->firstOrCreate(['id' => 'u1']), $role, $reach);

        return AdministeredScope::refusal($operation, $operation->toResourceReference(), $reach, $checks);
    }

    /**
     * Return further checks for the actor, allowing or denying every check, and
     * gathering the sources given, recording what was asked, in the scope in
     * place.
     *
     * @param  bool  $allowed
     * @param  \SineMacula\Laravel\Authorization\Evaluation\CheckSources|null  $sources
     * @return \SineMacula\Laravel\Authorization\Administration\FurtherChecks
     */
    private function checks(bool $allowed, ?CheckSources $sources): FurtherChecks
    {
        $decide = function (string $action, ?ResourceReference $on) use ($allowed): Decision {
            $this->record('decide', $action);

            self::assertSame('authorization:operation', $on?->type);

            return $allowed ? Decision::allow(DecisionStage::ALLOW) : Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT);
        };

        $gather = function (string $action) use ($sources): ?CheckSources {
            $this->record('sources', $action);

            return $sources;
        };

        $actor = StubIdentity::query()->firstOrCreate(['id' => 'admin']);

        return new FurtherChecks(new Subject($actor, $actor), $decide, $gather);
    }

    /**
     * Record what was asked, in the scope in place.
     *
     * @param  string  $kind
     * @param  string  $action
     * @return void
     */
    private function record(string $kind, string $action): void
    {
        $this->asked[] = [$kind, $action, TenantScope::currentApplication(), TenantScope::isBelowTenant(), TenantScope::currentTenant()];
    }

    /**
     * Return the sources of a check: the policies and boundaries of the
     * statements given, and a session cap of the patterns given, if any.
     *
     * @param  list<array<string, mixed>>  $policies
     * @param  list<array<string, mixed>>  $boundaries
     * @param  list<string>|null  $caps
     * @return \SineMacula\Laravel\Authorization\Evaluation\CheckSources
     *
     * @throws \Throwable
     */
    private static function sources(array $policies = [], array $boundaries = [], ?array $caps = null): CheckSources
    {
        $parse   = static fn (array $statement): EvaluationPolicy => EvaluationPolicy::fromArray(['name' => 'policy', 'statements' => [$statement]]);
        $session = new SessionCaps($caps === null ? [] : [['call', $caps]]);

        return new CheckSources(\array_map($parse, $policies), null, \array_map($parse, $boundaries), new CheckContext, static fn (): ?string => null, $session);
    }

    /**
     * Return a role, created on first use, carrying a policy that denies the
     * action.
     *
     * @param  string  $action
     * @return \SineMacula\Laravel\Authorization\Models\Role
     *
     * @throws \Throwable
     */
    private static function denyingRole(string $action): Role
    {
        $role   = Role::query()->create(['name' => 'restricted', 'rank' => 8]);
        $policy = Policy::query()->create(['name' => 'restricting', 'document' => ['statements' => [['effect' => 'deny', 'actions' => [$action]]]]]);

        self::grants()->attachPolicy($role, $policy);

        return $role;
    }

    /**
     * Bind a tenant tree of a parent and its child, and return both.
     *
     * @return array{\Tests\Feature\Stubs\StubTenant, \Tests\Feature\Stubs\StubTenant}
     */
    private function tree(): array
    {
        [$parent, $child] = \array_map(self::createTenant(...), ['parent', 'child']);

        $this->app?->instance(TenantTree::class, (new StubTenantTree)->put(Reference::of($child), Reference::of($parent)));

        return [$parent, $child];
    }

    /**
     * Return the administrator's identity.
     *
     * @return \Tests\Feature\Stubs\StubIdentity
     */
    private static function actorModel(): StubIdentity
    {
        return StubIdentity::query()->findOrFail('admin-1');
    }

    /**
     * Return the grant service.
     *
     * @return \SineMacula\Laravel\Authorization\Services\GrantService
     */
    private static function grants(): GrantService
    {
        $service = GrantService::instance();

        self::assertInstanceOf(GrantService::class, $service);

        return $service;
    }
}
