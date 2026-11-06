<?php

declare(strict_types = 1);

namespace Tests\Feature\Support;

use Illuminate\Database\Eloquent\Model;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Contracts\ResourceTenantResolver;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect;
use SineMacula\Laravel\Authorization\Evaluation\Policy;
use SineMacula\Laravel\Authorization\Evaluation\Statement;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResolvedTenant;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use SineMacula\Laravel\Authorization\Support\ResourceScope;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubSubjectResolver;
use Tests\Feature\Stubs\StubTenant;
use Tests\Feature\Stubs\StubTenantTree;
use Tests\TestCase;

/**
 * Feature tests for the scope a check on a tenant-owned resource is decided in:
 * the request's for a resource with no tenant, the resource's own for one of
 * the active tenant or below it, the platform's for one out of scope that a
 * platform-wide grant covers, and none at all, as `tenant_scope`, otherwise.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(ResourceScope::class)]
final class ResourceScopeTest extends TestCase
{
    /** @var \Tests\Feature\Stubs\StubTenant The organisation, at the top of the tree. */
    private StubTenant $org;

    /** @var \Tests\Feature\Stubs\StubTenant The account, below the organisation. */
    private StubTenant $account;

    /** @var \Tests\Feature\Stubs\StubTenant The sibling, below the organisation beside the account. */
    private StubTenant $sibling;

    /** @var \Tests\Feature\Stubs\StubIdentity The user the checks are about. */
    private StubIdentity $user;

    /**
     * Create the organisation with the account and its sibling below it, bind
     * the tree, and create the user and the permissions the tests grant.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        [$this->org, $this->account, $this->sibling] = \array_map(
            static fn (string $id): StubTenant => StubTenant::query()->create(['id' => $id, 'name' => $id]),
            ['org', 'account', 'sibling'],
        );

        $this->app?->instance(TenantTree::class, (new StubTenantTree)
            ->put(Reference::of($this->account), Reference::of($this->org))
            ->put(Reference::of($this->sibling), Reference::of($this->org)));

        $this->user = StubIdentity::query()->create(['id' => 'user-1']);

        Permission::create(['name' => 'posts:edit']);
        Permission::create(['name' => 'posts:archive']);
    }

    /**
     * A resource with no tenant is decided where the request is: in its tenant
     * and application, by the callback's own decision.
     *
     * @return void
     */
    public function testAResourceWithNoTenantIsDecidedWhereTheRequestIs(): void
    {
        $subject = $this->request($this->account);
        $allowed = Decision::allow(DecisionStage::ALLOW);

        $decision = ResourceScope::decide($subject, 'posts:edit', new ResourceReference('post:1'), function () use (&$seen, $allowed): Decision {
            $seen = $this->scope();

            return $allowed;
        });

        self::assertSame($allowed, $decision);
        self::assertEquals([[Reference::of($this->account), Reference::of($this->org)], 'web'], $seen);
    }

    /**
     * A resource of the active tenant is decided in that tenant, where a grant
     * the subject holds there allows it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAResourceOfTheActiveTenantIsDecidedThere(): void
    {
        $subject = $this->request($this->account);
        $post    = $this->postOf($this->account);

        ResourceScope::decide($subject, 'posts:edit', $post, function () use (&$seen): Decision {
            $seen = $this->scope();

            return Decision::allow(DecisionStage::ALLOW);
        });

        self::assertEquals([[Reference::of($this->account), Reference::of($this->org)], 'web'], $seen);
        self::assertFalse(Authorization::for($this->user)->check('posts:edit', $post)->isAllowed());

        $this->user->givePermission('posts:edit', null, $this->account);

        self::assertTrue(Authorization::for($this->user)->check('posts:edit', $post)->isAllowed());
    }

    /**
     * A resource of a tenant below the active one is decided in the resource's
     * tenant, so a grant held only there counts, though it would not in the
     * active tenant.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAResourceBelowTheActiveTenantIsDecidedInItsOwnTenant(): void
    {
        $subject = $this->request($this->org);
        $post    = $this->postOf($this->account);

        ResourceScope::decide($subject, 'posts:edit', $post, function () use (&$seen): Decision {
            $seen = $this->scope();

            return Decision::allow(DecisionStage::ALLOW);
        });

        self::assertEquals([[Reference::of($this->account), Reference::of($this->org)], 'web'], $seen);

        $this->user->givePermission('posts:edit', null, $this->account, false);

        self::assertFalse(Authorization::for($this->user)->check('posts:edit')->isAllowed());
        self::assertTrue(Authorization::for($this->user)->check('posts:edit', $post)->isAllowed());
    }

    /**
     * A grant in the active tenant that reaches the tenants below it counts for
     * a resource of a tenant below; one that does not reach below does not.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGrantInTheActiveTenantReachingBelowCounts(): void
    {
        $this->request($this->org);

        $post = $this->postOf($this->account);

        Role::create(['name' => 'editor'])->givePermission('posts:edit');
        Role::create(['name' => 'archivist'])->givePermission('posts:archive');

        $this->user->assignRole('editor', null, $this->org);
        $this->user->assignRole('archivist', null, $this->org, false);

        self::assertTrue(Authorization::for($this->user)->check('posts:edit', $post)->isAllowed());
        self::assertTrue(Authorization::for($this->user)->check('posts:archive')->isAllowed());
        self::assertFalse(Authorization::for($this->user)->check('posts:archive', $post)->isAllowed());
    }

    /**
     * A resource of a sibling tenant is denied as `tenant_scope` at the tenant
     * stage, before any policy is read: an allowing policy and a grant in the
     * sibling both go unseen, and the callback never runs.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAResourceOfASiblingTenantIsDeniedAsOutOfScope(): void
    {
        $subject = $this->request($this->account);
        $post    = $this->postOf($this->sibling);

        $this->user->givePermission('posts:edit', null, $this->sibling);
        $this->user->givePermission('posts:edit', null, $this->account);

        $decision = ResourceScope::decide($subject, 'posts:edit', $post, static fn (): never => self::fail('The callback ran.'));

        self::assertSame(DecisionReason::TENANT_SCOPE, $decision->reason);
        self::assertSame(DecisionStage::TENANT, $decision->stage);

        $checked = Authorization::for($this->user)->withPolicies([self::allowEverything()])->check('posts:edit', $post);

        self::assertFalse($checked->isAllowed());
        self::assertSame(DecisionReason::TENANT_SCOPE, $checked->reason);
        self::assertSame(DecisionStage::TENANT, $checked->stage);
        self::assertSame([], $checked->trace);
    }

    /**
     * A resource out of scope that the subject's platform-wide grant of the
     * action covers is decided at platform scope, in the request's application,
     * and allowed by that grant; a tenant grant counts neither to reach it nor
     * inside it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPlatformWideGrantDecidesOutOfScopeAtPlatformScope(): void
    {
        $subject = $this->request($this->account);
        $post    = $this->postOf($this->sibling);

        $this->user->givePermission('posts:edit');
        $this->user->givePermission('posts:archive', null, $this->sibling);
        $this->user->givePermission('posts:archive', null, $this->account);

        ResourceScope::decide($subject, 'posts:edit', $post, function () use (&$seen, &$archives): Decision {
            $seen     = $this->scope();
            $archives = $this->user->hasPermission('posts:archive');

            return Decision::allow(DecisionStage::ALLOW);
        });

        self::assertEquals([[], 'web'], $seen);
        self::assertFalse($archives);
        self::assertTrue(Authorization::for($this->user)->check('posts:edit', $post)->isAllowed());

        $archive = Authorization::for($this->user)->check('posts:archive', $post);

        self::assertSame(DecisionReason::TENANT_SCOPE, $archive->reason);
        self::assertSame(DecisionStage::TENANT, $archive->stage);
        self::assertEquals([Reference::of($this->account), Reference::of($this->org)], TenantScope::currentChain()->tenants);
    }

    /**
     * With no active tenant, every tenant-owned resource is out of scope, the
     * top of the tree's included, unless a platform-wide grant covers it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWithNoActiveTenantEveryTenantOwnedResourceIsOutOfScope(): void
    {
        $this->request(null);

        $this->user->givePermission('posts:edit', null, $this->org);
        $this->user->givePermission('posts:archive');

        foreach ([$this->org, $this->account] as $tenant) {
            $decision = Authorization::for($this->user)->check('posts:edit', $this->postOf($tenant));

            self::assertSame(DecisionReason::TENANT_SCOPE, $decision->reason);
            self::assertSame(DecisionStage::TENANT, $decision->stage);
            self::assertTrue(Authorization::for($this->user)->check('posts:archive', $this->postOf($tenant))->isAllowed());
        }
    }

    /**
     * The application stays the request's in every scope a resource is decided
     * in, and once the decision is made the request's tenant and application
     * are in place again.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheApplicationStaysTheRequestsInside(): void
    {
        $subject = $this->request($this->org, 'admin');

        $this->user->givePermission('posts:edit');

        $applications = [];

        foreach ([$this->postOf($this->org), $this->postOf($this->account), new ResourceReference('post:1')] as $post) {
            ResourceScope::decide($subject, 'posts:edit', $post, static function () use (&$applications): Decision {
                $applications[] = TenantScope::currentApplication();

                return Decision::allow(DecisionStage::ALLOW);
            });
        }

        $this->request($this->account, 'admin');

        ResourceScope::decide($subject, 'posts:edit', $this->postOf($this->sibling), static function () use (&$applications): Decision {
            $applications[] = TenantScope::currentApplication();

            return Decision::allow(DecisionStage::ALLOW);
        });

        self::assertSame(['admin', 'admin', 'admin', 'admin'], $applications);
        self::assertSame('admin', TenantScope::currentApplication());
        self::assertEquals([Reference::of($this->account), Reference::of($this->org)], TenantScope::currentChain()->tenants);
    }

    /**
     * A model's tenant is read through the bound resource tenant resolver, so a
     * model of a sibling tenant is out of scope and one of the active tenant is
     * decided there.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAModelsTenantIsReadThroughTheBoundResolver(): void
    {
        $this->request($this->account);

        $owners = ['in' => $this->account, 'out' => $this->sibling];

        $this->app?->instance(ResourceTenantResolver::class, new class ($owners) implements ResourceTenantResolver {
            /**
             * Create a resolver reading each model's tenant from its key.
             *
             * @param  array<string, \Tests\Feature\Stubs\StubTenant>  $owners
             */
            public function __construct(

                /** Each model's tenant, keyed by the model's key. */
                private readonly array $owners,
            ) {}

            /**
             * Return the tenant the model's key names.
             *
             * @param  \Illuminate\Database\Eloquent\Model  $resource
             * @return \SineMacula\Laravel\Authorization\Support\Reference|null
             */
            #[\Override]
            public function tenantOf(Model $resource): ?Reference
            {
                $owner = $this->owners[(string) $resource->getKey()] ?? null; // @phpstan-ignore cast.string

                return $owner === null ? null : Reference::of($owner);
            }

            /**
             * Return the tenant the pair's id names.
             *
             * @param  string  $type
             * @param  string  $id
             * @return \SineMacula\Laravel\Authorization\Support\Reference|null
             */
            #[\Override]
            public function tenantOfRecord(string $type, string $id): ?Reference
            {
                $owner = $this->owners[$id] ?? null;

                return $owner === null ? null : Reference::of($owner);
            }
        });

        $this->user->givePermission('posts:edit', null, $this->account);

        $out = Authorization::for($this->user)->check('posts:edit', StubIdentity::query()->create(['id' => 'out']));

        self::assertSame(DecisionReason::TENANT_SCOPE, $out->reason);
        self::assertTrue(Authorization::for($this->user)->check('posts:edit', StubIdentity::query()->create(['id' => 'in']))->isAllowed());
    }

    /**
     * An application that binds its subject resolver with `bind()`, so every
     * `make()` builds a new one, still has a resource decided in the scope its
     * tenant calls for: a resource of a tenant below the active one in that
     * tenant, where a grant held only there counts, and one of a sibling tenant
     * denied as `tenant_scope`, since a grant in the active tenant is not a
     * platform-wide one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAResolverBoundAfreshStillDecidesInTheResourcesScope(): void
    {
        $this->requestBoundAfresh($this->org);

        $this->user->givePermission('posts:edit', null, $this->account, false);

        self::assertFalse(Authorization::for($this->user)->check('posts:edit')->isAllowed());
        self::assertTrue(Authorization::for($this->user)->check('posts:edit', $this->postOf($this->account))->isAllowed());

        $this->requestBoundAfresh($this->account);

        $this->user->givePermission('posts:archive', null, $this->account);
        $this->user->givePermission('posts:archive', null, $this->sibling);

        $decision = Authorization::for($this->user)->check('posts:archive', $this->postOf($this->sibling));

        self::assertSame(DecisionReason::TENANT_SCOPE, $decision->reason);
        self::assertSame(DecisionStage::TENANT, $decision->stage);
        self::assertTrue(Authorization::for($this->user)->check('posts:archive', $this->postOf($this->account))->isAllowed());
    }

    /**
     * Make the request one in the given tenant, or none, and application, and
     * return the subject it resolves for the user.
     *
     * @param  \Tests\Feature\Stubs\StubTenant|null  $tenant
     * @param  string  $application
     * @return \SineMacula\Laravel\Authorization\Subject
     */
    private function request(?StubTenant $tenant, string $application = 'web'): Subject
    {
        $resolver = new StubSubjectResolver($this->user, $tenant, $application);

        $this->app?->instance(SubjectResolver::class, $resolver);
        $this->app?->forgetInstance(ResolvedTenant::class);

        return $resolver->forUser($this->user);
    }

    /**
     * Make the request one in the given tenant, in the web application, under a
     * subject resolver bound with `bind()`, so every `make()` builds a new one.
     *
     * @param  \Tests\Feature\Stubs\StubTenant  $tenant
     * @return void
     */
    private function requestBoundAfresh(StubTenant $tenant): void
    {
        $this->app?->bind(SubjectResolver::class, fn (): SubjectResolver => new StubSubjectResolver($this->user, $tenant, 'web'));
        $this->app?->forgetInstance(ResolvedTenant::class);
    }

    /**
     * Return a reference to a post the given tenant owns.
     *
     * @param  \Tests\Feature\Stubs\StubTenant  $tenant
     * @return \SineMacula\Laravel\Authorization\Support\ResourceReference
     */
    private function postOf(StubTenant $tenant): ResourceReference
    {
        return ResourceReference::record('post', '1', Reference::of($tenant));
    }

    /**
     * Return the tenants of the current chain and the current application.
     *
     * @return array{0: list<\SineMacula\Laravel\Authorization\Support\Reference>, 1: string|null}
     */
    private function scope(): array
    {
        return [TenantScope::currentChain()->tenants, TenantScope::currentApplication()];
    }

    /**
     * Return a policy allowing every action on every resource.
     *
     * @return \SineMacula\Laravel\Authorization\Evaluation\Policy
     */
    private static function allowEverything(): Policy
    {
        return new Policy('allow-everything', [new Statement(PolicyEffect::ALLOW, ['*'], ['*'])]);
    }
}
