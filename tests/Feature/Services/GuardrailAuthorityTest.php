<?php

declare(strict_types = 1);

namespace Tests\Feature\Services;

use Illuminate\Container\Container;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\Enums\TraceOutcome;
use SineMacula\Laravel\Authorization\Evaluation\TraceEntry;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Exceptions\GuardrailException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Services\Support\GuardrailAuthority;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\ActsAsTenant;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubTenant;
use Tests\Feature\Stubs\StubTenantTree;
use Tests\Feature\Stubs\SuspendableIdentity;
use Tests\TestCase;

/**
 * Feature tests for who may change the guardrails of a scope: only an actor
 * holding the right to manage guardrails, effectively, through a grant whose
 * reach covers the scope from above it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(GuardrailAuthority::class)]
final class GuardrailAuthorityTest extends TestCase
{
    use ActsAsTenant;

    /** @var \Tests\Feature\Stubs\StubTenant The organisation, the root of the tree. */
    private StubTenant $org;

    /** @var \Tests\Feature\Stubs\StubTenant An account below the organisation. */
    private StubTenant $account;

    /** @var \Tests\Feature\Stubs\StubTenant A team below the account. */
    private StubTenant $team;

    /**
     * Bind a tree of a team below an account below an organisation.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        [$this->org, $this->account, $this->team] = \array_map(self::createTenant(...), ['org', 'account', 'team']);

        $tree = (new StubTenantTree)->put(Reference::of($this->account), Reference::of($this->org))->put(Reference::of($this->team), Reference::of($this->account));

        $this->app?->instance(TenantTree::class, $tree);
    }

    /**
     * A platform-wide grant of the right lets the actor change the platform's
     * guardrails and every tenant's.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public function testAPlatformGrantChangesEveryScope(): void
    {
        $actor = self::actor('platform-admin');

        $actor->givePermission(self::right());

        foreach ([null, $this->org, $this->account, $this->team] as $tenant) {
            self::assertPermitted($actor, $tenant);
        }
    }

    /**
     * A grant held at an ancestor that reaches the tenants below it lets the
     * actor change the guardrails of every tenant below, never those of the
     * ancestor itself, nor the platform's.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public function testAnAncestorsGrantChangesTheTenantsBelowIt(): void
    {
        $actor = self::actor('org-admin');

        $actor->givePermission(self::right(), tenant: $this->org);

        self::assertPermitted($actor, $this->account);
        self::assertPermitted($actor, $this->team);
        self::assertRefused($actor, $this->org);
        self::assertRefused($actor, null);
    }

    /**
     * A grant held at an ancestor that does not reach below it changes nothing
     * below, and a grant held within the tenant itself never changes its own
     * guardrails, only those of the tenants below it.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public function testAGrantThatDoesNotReachTheTenantFromAboveIsRefused(): void
    {
        $alone  = self::actor('org-only');
        $within = self::actor('account-admin');

        $alone->givePermission(self::right(), tenant: $this->org, includeSubtree: false);
        $within->givePermission(self::right(), tenant: $this->account);

        self::assertRefused($alone, $this->account);
        self::assertRefused($alone, $this->team);
        self::assertRefused($within, $this->account);
        self::assertPermitted($within, $this->team);
        self::assertRefused($within, null);
    }

    /**
     * A tenant at the root of the tree is changed from the platform alone, so a
     * grant held within it is refused.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public function testARootTenantIsChangedFromThePlatform(): void
    {
        $actor = self::actor('org-admin');

        $actor->givePermission(self::right(), tenant: $this->org);

        self::assertRefused($actor, $this->org);
    }

    /**
     * An actor without the right is refused everywhere, the platform included,
     * whatever else it holds.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public function testAnActorWithoutTheRightIsRefused(): void
    {
        $actor = self::actor('editor');

        $actor->givePermission(Permission::create(['name' => 'posts:edit']));

        foreach ([null, $this->org, $this->account] as $tenant) {
            self::assertRefused($actor, $tenant);
        }
    }

    /**
     * The right counts held through a role granted from above, and the
     * request's tenant has no bearing on where it is decided.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public function testTheRightCountsThroughARole(): void
    {
        $actor = self::actor('role-admin');
        $role  = Role::create(['name' => 'guardian']);

        $role->givePermission(self::right());
        $actor->assignRole($role, tenant: $this->org);
        $this->actAsTenant($this->team);

        self::assertPermitted($actor, $this->account);
        self::assertRefused($actor, $this->org);
    }

    /**
     * The right is held effectively: a deny the actor holds, or an inactive
     * actor, is refused though the grant covers the scope.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheRightIsHeldEffectively(): void
    {
        $denied   = self::actor('denied');
        $inactive = SuspendableIdentity::create(['id' => 'suspended']);

        $denied->givePermission(self::right());
        $denied->attachPolicy(Policy::create(['name' => 'no-guardrails', 'document' => ['statements' => [['effect' => 'deny', 'actions' => ['authorization:*']]]]]));
        $inactive->givePermission(self::right());

        $inactive->suspended = true;

        self::assertRefused($denied, $this->account);
        self::assertRefused($inactive, $this->account);
    }

    /**
     * The guardrails never count: guardrails on the platform and on an ancestor
     * that deny the right, and one that cannot be read, leave the actor
     * permitted, and the decision records the guardrail stage as exempt.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public function testTheGuardrailsNeverCountAgainstTheRight(): void
    {
        $actor   = self::actor('platform-admin');
        $denying = Policy::create(['name' => 'denying', 'document' => ['statements' => [['effect' => 'deny', 'actions' => ['authorization:*']]]]]);
        $broken  = Policy::create(['name' => 'broken', 'document' => ['statements' => [['effect' => 'allow', 'actions' => ['posts:read']]]]]);

        $actor->givePermission(self::right());

        DB::table('guardrails')->insert([
            ['policy_id' => $denying->id, 'tenant_type' => null, 'tenant_id' => null],
            ['policy_id' => $denying->id, 'tenant_type' => $this->org->getMorphClass(), 'tenant_id' => 'org'],
            ['policy_id' => $broken->id, 'tenant_type' => null, 'tenant_id' => null],
        ]);
        DB::table('policies')->where('id', $broken->id)->update(['document' => '{"statements": "broken"}']);

        Event::fake([DecisionEvaluated::class]);

        self::assertPermitted($actor, null);
        self::assertPermitted($actor, $this->org);
        self::assertPermitted($actor, $this->team);

        $isExempt = static fn (TraceEntry $entry): bool => $entry->stage === DecisionStage::GUARDRAIL && $entry->outcome === TraceOutcome::EXEMPT;
        $exempt   = static fn (DecisionEvaluated $event): bool => $event->decision->isAllowed() && \array_filter($event->decision->trace, $isExempt) !== [];

        Event::assertDispatchedTimes(DecisionEvaluated::class, 3);
        Event::assertDispatched(DecisionEvaluated::class, $exempt);
        Event::assertNotDispatched(DecisionEvaluated::class, static fn (DecisionEvaluated $event): bool => !$exempt($event));
    }

    /**
     * The right is decided through the one decision path, so the decision is
     * reported like any other, and the request's tenant is in place again
     * afterwards.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public function testTheRightIsDecidedThroughCheck(): void
    {
        $actor = self::actor('platform-admin');

        $actor->givePermission(self::right());
        $this->actAsTenant($this->team);

        Event::fake([DecisionEvaluated::class]);

        GuardrailAuthority::assertPermitted(self::acting($actor), Reference::of($this->account));

        $decided = static fn (DecisionEvaluated $event): bool => $event->action === PackagePermissions::GUARDRAIL_MANAGE && $event->decision->isAllowed();

        Event::assertDispatched(DecisionEvaluated::class, $decided);
        self::assertSame([$this->team->getMorphClass(), 'team'], TenantScope::currentTenant());
        self::assertFalse(TenantScope::isBelowTenant());
    }

    /**
     * An actor someone is impersonating is refused as impersonating, with the
     * decision, though it holds the right from above the scope, unless it is
     * also allowed `authorization:administration.impersonated` there, decided
     * from above the scope as the right is.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnImpersonatedActorNeedsTheImpersonatedRight(): void
    {
        $actor = self::actor('org-admin');

        $actor->givePermission(self::right(), tenant: $this->org);

        $impersonated = self::acting($actor)->impersonatedBy(new Reference('support', '9'));
        $refused      = self::impersonationRefusal($impersonated, $this->account);

        $trace = $refused?->getDecision()->trace ?? [];

        self::assertSame(DecisionStage::ADMINISTRATION, $refused?->getDecision()?->stage);
        self::assertEquals(new TraceEntry(DecisionStage::ADMINISTRATION, TraceOutcome::REFUSED, null, [], 'administration.impersonating'), \array_reverse($trace)[0] ?? null);

        $impersonatedRight = Permission::create(['name' => PackagePermissions::ADMINISTRATION_IMPERSONATED]);

        $actor->givePermission($impersonatedRight, tenant: $this->account);

        self::assertNotNull(self::impersonationRefusal($impersonated, $this->account));

        $actor->givePermission($impersonatedRight, tenant: $this->org);

        self::assertNull(self::impersonationRefusal($impersonated, $this->account));
        self::assertPermitted($actor, $this->account);
    }

    /**
     * With no authorization manager bound, every actor is refused.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public function testWithoutAManagerEveryActorIsRefused(): void
    {
        $actor = self::actor('platform-admin');

        $actor->givePermission(self::right());

        $container = Container::getInstance();

        Container::setInstance(new Container);

        try {
            self::assertRefused($actor, null);
        } finally {
            Container::setInstance($container);
        }
    }

    /**
     * Return the refusal of the impersonated actor's change to the guardrails
     * of the tenant, which must be as impersonating, or null when it is
     * permitted.
     *
     * @param  \SineMacula\Laravel\Authorization\Administration\ActingContext  $actor
     * @param  \Tests\Feature\Stubs\StubTenant  $tenant
     * @return \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException|null
     */
    private static function impersonationRefusal(ActingContext $actor, StubTenant $tenant): ?AuthorizationException
    {
        try {
            GuardrailAuthority::assertPermitted($actor, Reference::of($tenant));
        } catch (AuthorizationException $exception) {
            self::assertSame(DecisionReason::ADMINISTRATION_IMPERSONATING, $exception->getReason());

            return $exception;
        }

        return null;
    }

    /**
     * Assert the actor may change the guardrails of the tenant, or of the
     * platform when it is null.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $actor
     * @param  \Tests\Feature\Stubs\StubTenant|null  $tenant
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    private static function assertPermitted(Model $actor, ?StubTenant $tenant): void
    {
        GuardrailAuthority::assertPermitted(self::acting($actor), $tenant === null ? null : Reference::of($tenant));

        self::assertTrue(true);
    }

    /**
     * Assert the actor is refused the guardrails of the tenant, or of the
     * platform when it is null, naming the reason, the actor and the scope.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $actor
     * @param  \Tests\Feature\Stubs\StubTenant|null  $tenant
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    private static function assertRefused(Model $actor, ?StubTenant $tenant): void
    {
        $scope = $tenant === null ? null : Reference::of($tenant);

        try {
            GuardrailAuthority::assertPermitted(self::acting($actor), $scope);
            self::fail('The actor was not refused.');
        } catch (GuardrailException $exception) {
            self::assertSame(GuardrailException::NOT_PERMITTED, $exception->getReason());
            self::assertEquals(Reference::of($actor), $exception->getActor());
            self::assertEquals([$scope], $exception->getTenants());
        }
    }

    /**
     * Return the acting context of the actor, its subject named as itself.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $actor
     * @return \SineMacula\Laravel\Authorization\Administration\ActingContext
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    private static function acting(Model $actor): ActingContext
    {
        return ActingContext::for(new Subject($actor, $actor));
    }

    /**
     * Create an identity with the key.
     *
     * @param  string  $id
     * @return \Tests\Feature\Stubs\StubIdentity
     */
    private static function actor(string $id): StubIdentity
    {
        return StubIdentity::create(['id' => $id]);
    }

    /**
     * Return the right to manage guardrails, created on first use.
     *
     * @return \SineMacula\Laravel\Authorization\Models\Permission
     */
    private static function right(): Permission
    {
        return Permission::query()->firstOrCreate(['name' => PackagePermissions::GUARDRAIL_MANAGE]);
    }
}
