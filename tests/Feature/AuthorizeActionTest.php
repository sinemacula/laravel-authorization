<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Translation\Translator;
use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Http\Middleware\TrustProxies;
use Illuminate\Routing\Middleware\SubstituteBindings;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Route;
use Illuminate\Translation\Translator as TranslatorImplementation;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Contracts\ResourceTenantResolver;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Events\AuthorizationFailed;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Authorization\Exceptions\AttributeProviderFailed;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Http\Middleware\AbstractAuthorizationMiddleware;
use SineMacula\Laravel\Authorization\Http\Middleware\AuthorizeAction;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\ChecksAccess;
use Tests\Feature\Stubs\FailingResourceAttributes;
use Tests\Feature\Stubs\FixedResourceTenantResolver;
use Tests\Feature\Stubs\RecordingResourceAttributes;
use Tests\Feature\Stubs\StubGrantee;
use Tests\Feature\Stubs\StubTenant;
use Tests\TestCase;

/**
 * Feature coverage for the `authorize` route middleware, which decides an
 * action on the model a route parameter binds.
 *
 * The routes bind `{post}` to a `StubTenant` row, named `post` in the morph
 * map, so a bound model is the resource `post:{key}`. A value that cannot be
 * identified, or a parameter the route does not carry, is denied by the
 * decision itself as `resource_unresolved`, as the Gate denies it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(AuthorizeAction::class)]
#[CoversClass(AbstractAuthorizationMiddleware::class)]
#[CoversClass(AuthorizationManager::class)]
final class AuthorizeActionTest extends TestCase
{
    use ChecksAccess;

    /** @var string Action reused across the scenarios. */
    private const string ACTION = 'posts:delete';

    /** @var array<string, class-string<\Illuminate\Database\Eloquent\Model>> The morph map before the test. */
    private array $morphMap = [];

    /**
     * Register the routes and the morph map the scenarios use.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->morphMap = Relation::morphMap();

        Relation::morphMap(['post' => StubTenant::class]);

        Route::middleware([SubstituteBindings::class, 'authorize:' . self::ACTION . ',post'])
            ->get('/posts/{post}', static fn (StubTenant $post): string => 'ok');

        Route::middleware('authorize:' . self::ACTION . ',report')
            ->get('/reports/{report}', static fn (string $report): string => 'ok');

        Route::middleware('authorize:posts:update|' . self::ACTION . ',missing')
            ->get('/unbound/{post}', static fn (string $post): string => 'ok');

        Route::middleware(['authorize:' . self::ACTION . ',post', SubstituteBindings::class])
            ->get('/early/{post}', static fn (StubTenant $post): string => 'ok');

        Route::middleware('authorize:' . self::ACTION)
            ->get('/posts', static fn (): string => 'ok');

        Route::middleware('authorize:posts:update|' . self::ACTION . ',post')
            ->get('/listed/{post}', static fn (string $post): string => 'ok');

        Route::middleware([SubstituteBindings::class, 'authorize:posts:update|' . self::ACTION . ',post'])
            ->get('/either/{post}', static fn (StubTenant $post): string => 'ok');

        Route::bind('draft', static fn (): StubTenant => new StubTenant);

        Route::middleware([SubstituteBindings::class, 'authorize:posts:update|' . self::ACTION . ',draft'])
            ->get('/drafts/{draft}', static fn (StubTenant $draft): string => 'ok');
    }

    /**
     * Restore the morph map the scenarios extended.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Relation::morphMap($this->morphMap, false);

        parent::tearDown();
    }

    /**
     * The bound model is the resource: a policy allowing the action on it
     * admits the request, and another model is denied with the reason code and
     * the translated message.
     *
     * @return void
     */
    public function testTheBoundModelIsTheResource(): void
    {
        StubTenant::create(['id' => 'post-1']);
        StubTenant::create(['id' => 'post-2']);

        $identity = StubGrantee::create(['id' => 'author']);
        self::attachStatement($identity, 'allow', [self::ACTION], ['post:post-1']);

        $this->actAs($identity);

        $this->getJson('/posts/post-1')->assertOk();
        $this->getJson('/posts/post-2')->assertForbidden()->assertJson(['message' => 'This action is unauthorized.']);

        $this->withoutExceptionHandling();

        $denial = self::denialOf(fn () => $this->get('/posts/post-2'));

        self::assertSame(DecisionReason::NO_MATCH, $denial->getReason());
    }

    /**
     * The bound model reaches the resource attribute provider, so the owner
     * rule admits the owner and refuses anyone else.
     *
     * @return void
     */
    public function testTheBoundModelReachesTheResourceAttributeProvider(): void
    {
        $post     = StubTenant::create(['id' => 'post-1']);
        $provider = new RecordingResourceAttributes;

        $this->app?->instance(RecordingResourceAttributes::class, $provider);
        $this->container()->make(ConfigRepository::class)->set('authorization.attributes.resources', ['post' => RecordingResourceAttributes::class]);

        $policy = Policy::create(['name' => 'owner-deletes', 'document' => ['statements' => [
            ['effect' => 'allow', 'actions' => [self::ACTION], 'conditions' => ['eq' => ['resource.owner.id' => '${subject.id}']]],
        ]]]);

        $owner = StubGrantee::create(['id' => '7']);
        $other = StubGrantee::create(['id' => '8']);

        $owner->attachPolicy($policy);
        $other->attachPolicy($policy);

        $this->actAs($owner);
        $this->getJson('/posts/post-1')->assertOk();

        $this->actAs($other);
        $this->getJson('/posts/post-1')->assertForbidden();

        self::assertCount(2, $provider->calls);
        self::assertTrue($post->is($provider->calls[0][1]));
    }

    /**
     * A resource attribute provider that fails reaches the caller as
     * `AttributeProviderFailed` through the Gate and the middleware, so a
     * routed request is a server error, never a refusal or an allow.
     *
     * @return void
     */
    public function testAFailingAttributeProviderIsAServerError(): void
    {
        $this->declarePermissionEnum();

        $post     = StubTenant::create(['id' => 'post-1']);
        $identity = self::identityHolding(permissions: [self::ACTION]);

        $this->container()->make(ConfigRepository::class)->set('authorization.attributes.resources', ['post' => FailingResourceAttributes::class]);

        $identity->attachPolicy(Policy::create(['name' => 'no-archived-deletes', 'document' => ['statements' => [
            ['effect' => 'deny', 'actions' => [self::ACTION], 'conditions' => ['eq_if_exists' => ['resource.status' => 'archived']]],
        ]]]));

        $this->actAs($identity);

        self::assertInstanceOf(AttributeProviderFailed::class, $this->getJson('/posts/post-1')->assertServerError()->exception);

        $this->expectException(AttributeProviderFailed::class);

        Gate::forUser($identity)->allows(self::ACTION, $post);
    }

    /**
     * An explicit deny on the bound model wins over a held permission.
     *
     * @return void
     */
    public function testAnExplicitDenyOnTheModelWinsOverAHeldPermission(): void
    {
        StubTenant::create(['id' => 'post-1']);
        StubTenant::create(['id' => 'post-2']);

        $identity = self::identityHolding(permissions: [self::ACTION]);
        self::attachStatement($identity, 'deny', [self::ACTION], ['post:post-1']);

        $this->actAs($identity);

        $this->getJson('/posts/post-2')->assertOk();

        $this->withoutExceptionHandling();

        self::assertSame(DecisionReason::EXPLICIT_DENY, self::denialOf(fn () => $this->get('/posts/post-1'))->getReason());
    }

    /**
     * A parameter nothing binds is the resource as given.
     *
     * @return void
     */
    public function testARawParameterIsTheResourceAsGiven(): void
    {
        $identity = StubGrantee::create(['id' => 'reader']);
        self::attachStatement($identity, 'allow', [self::ACTION], ['report-7']);

        $this->actAs($identity);

        $this->getJson('/reports/report-7')->assertOk();
        $this->getJson('/reports/report-8')->assertForbidden();
    }

    /**
     * A raw parameter holding a NUL byte names nothing: it denies as
     * `resource_unresolved`, even under a statement allowing the action on
     * every resource, and never reaches a pattern match.
     *
     * @return void
     */
    public function testARawParameterHoldingANulByteDenies(): void
    {
        Event::fake([DecisionEvaluated::class, AuthorizationFailed::class]);

        $identity = StubGrantee::create(['id' => 'reader']);
        self::attachStatement($identity, 'allow', [self::ACTION], ['*']);

        $this->actAs($identity);

        $this->getJson('/reports/report-7')->assertOk();
        $this->getJson('/reports/report-7%00')->assertForbidden();

        Event::assertDispatched(DecisionEvaluated::class, static fn (DecisionEvaluated $event): bool => $event->resource === null
            && $event->reason                                                                                            === DecisionReason::RESOURCE_UNRESOLVED);
    }

    /**
     * A parameter nothing binds is the caller's own text, an opaque identifier,
     * even when it spells a model class: it is never read as the class's type
     * (`post:*`), so a statement on every post does not admit it.
     *
     * @return void
     */
    public function testARawParameterSpellingAModelClassIsNotItsType(): void
    {
        Event::fake([DecisionEvaluated::class, AuthorizationFailed::class]);

        $identity = StubGrantee::create(['id' => 'reader']);
        self::attachStatement($identity, 'allow', [self::ACTION], ['post:*']);

        $this->actAs($identity);

        $this->getJson('/reports/' . \rawurlencode(StubTenant::class))->assertForbidden();

        Event::assertDispatched(DecisionEvaluated::class, static fn (DecisionEvaluated $event): bool => $event->resource === StubTenant::class
            && $event->reason                                                                                            === DecisionReason::NO_MATCH);
    }

    /**
     * The bound model is resolved once for every listed action, so the resource
     * tenant resolver is asked about it once, however many of the actions are
     * checked, and each check is about the model.
     *
     * @return void
     */
    public function testTheBoundModelIsResolvedOnceForEveryListedAction(): void
    {
        Event::fake([DecisionEvaluated::class, AuthorizationFailed::class]);

        $post     = StubTenant::create(['id' => 'post-1']);
        $resolver = new FixedResourceTenantResolver;

        $this->app?->instance(ResourceTenantResolver::class, $resolver);

        $this->actAs(StubGrantee::create(['id' => 'bystander']));

        $this->getJson('/either/post-1')->assertForbidden();

        self::assertCount(1, $resolver->asked);
        self::assertTrue($resolver->asked[0]->is($post));
        Event::assertDispatchedTimes(DecisionEvaluated::class, 2);
        Event::assertDispatched(AuthorizationFailed::class, static fn (AuthorizationFailed $event): bool => $event->resource === 'post:post-1');

        foreach (['posts:update', self::ACTION] as $action) {
            Event::assertDispatched(DecisionEvaluated::class, static fn (DecisionEvaluated $event): bool => $event->action === $action
                && $event->resource                                                                                        === 'post:post-1');
        }
    }

    /**
     * A value that cannot be identified (an unsaved model) denies, even when a
     * policy allows the action on every resource. Each listed action is denied
     * at the resource stage about no resource, and only the last fires
     * `AuthorizationFailed`, as a denied list does.
     *
     * @return void
     */
    public function testAnUnidentifiableValueDenies(): void
    {
        $this->allowEverySubject(['posts:update', self::ACTION]);
        $this->actAs(StubGrantee::create(['id' => 'drafter']));

        $this->assertRefusedOnce('/drafts/new');
    }

    /**
     * A parameter the route does not carry denies rather than turning the check
     * into one about no resource, and is refused as an unidentifiable value is.
     *
     * @return void
     */
    public function testAParameterTheRouteDoesNotCarryDenies(): void
    {
        $this->allowEverySubject(['posts:update', self::ACTION]);
        $this->actAs(StubGrantee::create(['id' => 'misrouted']));

        $this->assertRefusedOnce('/unbound/post-1');
    }

    /**
     * Declared before `SubstituteBindings`, the middleware still runs after it,
     * so it decides on the bound model: an explicit deny on the model wins over
     * a held permission, as the Gate decides.
     *
     * @return void
     */
    public function testTheMiddlewareRunsAfterBindingWhereverItIsDeclared(): void
    {
        $this->declarePermissionEnum();

        $post     = StubTenant::create(['id' => 'post-1']);
        $identity = self::identityHolding(permissions: [self::ACTION]);
        self::attachStatement($identity, 'deny', [self::ACTION], ['post:post-1']);

        $this->actAs($identity);

        self::assertFalse(Gate::forUser($identity)->allows(self::ACTION, $post));

        $this->getJson('/early/post-1')->assertForbidden();

        $this->withoutExceptionHandling();

        self::assertSame(DecisionReason::EXPLICIT_DENY, self::denialOf(fn () => $this->get('/early/post-1'))->getReason());
    }

    /**
     * Every denial is worded in the translator's current locale: a decided one
     * on a bound model, an unidentifiable value and a missing parameter.
     *
     * @return void
     */
    public function testDenialsAreTranslatedInTheCurrentLocale(): void
    {
        $translator = $this->app?->make(Translator::class);
        self::assertInstanceOf(TranslatorImplementation::class, $translator);

        $translator->addLines(['authorization.denied' => 'Action non autorisée.'], 'fr', 'authorization');
        $translator->setLocale('fr');

        StubTenant::create(['id' => 'post-1']);

        $this->allowEverySubject(['posts:update']);
        $this->actAs(StubGrantee::create(['id' => 'francophone']));

        foreach (['/posts/post-1', '/drafts/new', '/unbound/post-1'] as $uri) {
            $this->getJson($uri)->assertForbidden()->assertJson(['message' => 'Action non autorisée.']);
        }
    }

    /**
     * Without a parameter the check is about no resource: a statement on every
     * resource allows it, one scoped to a resource does not.
     *
     * @return void
     */
    public function testWithoutAParameterTheCheckIsResourceLess(): void
    {
        $everything = StubGrantee::create(['id' => 'everything']);
        $scoped     = StubGrantee::create(['id' => 'scoped']);

        self::attachStatement($everything, 'allow', [self::ACTION]);
        self::attachStatement($scoped, 'allow', [self::ACTION], ['post:post-1']);

        $this->actAs($everything);
        $this->getJson('/posts')->assertOk();

        $this->actAs($scoped);
        $this->getJson('/posts')->assertForbidden();
    }

    /**
     * Any one allowed action of a `|` list admits the request.
     *
     * @return void
     */
    public function testAnyAllowedActionOfAListIsEnough(): void
    {
        $identity = StubGrantee::create(['id' => 'lister']);
        self::attachStatement($identity, 'allow', [self::ACTION], ['post-1']);

        $this->actAs($identity);

        $this->getJson('/listed/post-1')->assertOk();
        $this->getJson('/listed/post-2')->assertForbidden();
    }

    /**
     * In a routed request the `request` namespace is the request's: its address
     * as the trusted proxies resolve it, its method and its route's name, never
     * what the caller passes. Outside a routed request it is absent, so its
     * keys are missing.
     *
     * @return void
     */
    public function testTheRequestNamespaceIsTheRoutedRequests(): void
    {
        Route::middleware('authorize:posts:update')->post('/drafts', static fn (): string => 'ok')->name('drafts.store');

        $identity = StubGrantee::create(['id' => 'author']);

        $identity->attachPolicy(Policy::create(['name' => 'from-the-office', 'document' => ['statements' => [
            ['effect' => 'allow', 'actions' => ['posts:update'], 'conditions' => [
                'ip_in' => ['request.ip' => '203.0.113.0/24'],
                'eq'    => ['request.method' => 'POST', 'request.route' => 'drafts.store'],
            ]],
            ['effect' => 'allow', 'actions' => [self::ACTION], 'conditions' => ['null' => ['request.ip' => true, 'request.route' => true]]],
        ]]]));

        $this->actAs($identity);

        self::assertFalse(Authorization::can('posts:update', null, ['request' => ['ip' => '203.0.113.7', 'method' => 'POST', 'route' => 'drafts.store']]));
        self::assertTrue(Authorization::can(self::ACTION));

        TrustProxies::at(['10.0.0.5']);

        try {
            $this->withServerVariables(['REMOTE_ADDR' => '10.0.0.5'])->withHeader('X-Forwarded-For', '203.0.113.7')->postJson('/drafts')->assertOk();
            $this->withServerVariables(['REMOTE_ADDR' => '10.0.0.6'])->withHeader('X-Forwarded-For', '203.0.113.7')->postJson('/drafts')->assertForbidden();
            $this->withServerVariables(['REMOTE_ADDR' => '10.0.0.6'])->postJson('/drafts', ['request' => ['ip' => '203.0.113.7']])->assertForbidden();
        } finally {
            TrustProxies::flushState();
        }

        $this->getJson('/posts')->assertForbidden();
    }

    /**
     * The off-network deny refuses a routed request from outside its ranges and
     * admits one from inside, and outside a routed request, where `request.ip`
     * is missing, it still denies, written `_if_exists` or not.
     *
     * @return void
     */
    public function testTheOffNetworkDenyRefusesOutsideTheRanges(): void
    {
        $strict   = StubGrantee::create(['id' => 'strict']);
        $optional = StubGrantee::create(['id' => 'optional']);

        foreach ([[$strict, 'ip_not_in'], [$optional, 'ip_not_in_if_exists']] as [$identity, $operator]) {
            $identity->attachPolicy(Policy::create(['name' => 'no-deletes-off-network-' . $operator, 'document' => ['statements' => [
                ['effect' => 'allow', 'actions' => [self::ACTION]],
                ['effect' => 'deny', 'actions' => [self::ACTION], 'conditions' => [$operator => ['request.ip' => ['10.0.0.0/8', '192.168.0.0/16']]]],
            ]]]));
        }

        self::assertSame(DecisionReason::EXPLICIT_DENY, Authorization::for($strict)->check(self::ACTION)->reason);
        self::assertSame(DecisionReason::EXPLICIT_DENY, Authorization::for($optional)->check(self::ACTION)->reason);

        foreach ([$strict, $optional] as $identity) {
            $this->actAs($identity);

            $this->withServerVariables(['REMOTE_ADDR' => '10.1.2.3'])->getJson('/posts')->assertOk();
            $this->withServerVariables(['REMOTE_ADDR' => '192.168.4.5'])->getJson('/posts')->assertOk();
            $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.7'])->getJson('/posts')->assertForbidden();
        }
    }

    /**
     * A request without a subject is unauthenticated.
     *
     * @return void
     */
    public function testARequestWithoutASubjectIsUnauthenticated(): void
    {
        StubTenant::create(['id' => 'post-1']);

        $this->actAs(null);

        $this->getJson('/posts/post-1')->assertUnauthorized();
    }

    /**
     * The middleware and the Gate answer the same about a bound model, for a
     * held permission, an explicit deny on the model and a policy on another.
     *
     * @return void
     */
    public function testTheMiddlewareAndTheGateAgree(): void
    {
        $this->declarePermissionEnum();

        $post      = StubTenant::create(['id' => 'post-1']);
        $held      = self::identityHolding(permissions: [self::ACTION]);
        $denied    = self::identityHolding(permissions: [self::ACTION]);
        $elsewhere = StubGrantee::create(['id' => 'elsewhere']);

        self::attachStatement($denied, 'deny', ['*'], ['post:post-1']);
        self::attachStatement($elsewhere, 'allow', [self::ACTION], ['post:post-2']);

        foreach ([[$held, true], [$denied, false], [$elsewhere, false]] as [$identity, $expected]) {
            $this->actAs($identity);

            self::assertSame($expected, Gate::forUser($identity)->allows(self::ACTION, $post));
            $this->getJson('/posts/post-1')->assertStatus($expected ? 200 : 403);
        }
    }

    /**
     * A bound model the resource tenant resolver places in a tenant is decided
     * in that tenant's scope: with no tenant active it is out of scope, and a
     * policy allowing the action on every resource is not read, so the request
     * is denied as `tenant_scope`. The resolver is asked about the bound model.
     *
     * @return void
     */
    public function testABoundModelOfATenantOutsideTheScopeIsDenied(): void
    {
        $post     = StubTenant::create(['id' => 'post-1']);
        $resolver = new FixedResourceTenantResolver(new Reference('org', 'org-1'));

        $this->app?->instance(ResourceTenantResolver::class, $resolver);

        $this->allowEverySubject([self::ACTION]);
        $this->actAs(StubGrantee::create(['id' => 'outsider']));

        $this->getJson('/posts/post-1')->assertForbidden();

        $this->withoutExceptionHandling();

        self::assertSame(DecisionReason::TENANT_SCOPE, self::denialOf(fn () => $this->get('/posts/post-1'))->getReason());
        self::assertNotSame([], $resolver->asked);

        foreach ($resolver->asked as $model) {
            self::assertTrue($model->is($post));
        }
    }

    /**
     * Assert the request is refused for an unidentifiable resource: a denial at
     * the resource stage about no resource recorded for each listed action, and
     * one `AuthorizationFailed` event, for the last.
     *
     * @param  string  $uri
     * @return void
     */
    private function assertRefusedOnce(string $uri): void
    {
        Event::fake([DecisionEvaluated::class, AuthorizationFailed::class]);

        $this->withoutExceptionHandling();

        $denial = self::denialOf(fn () => $this->get($uri));

        self::assertSame(DecisionReason::RESOURCE_UNRESOLVED, $denial->getReason());
        self::assertSame('This action is unauthorized.', $denial->getMessage());
        Event::assertDispatchedTimes(DecisionEvaluated::class, 2);

        foreach (['posts:update', self::ACTION] as $action) {
            Event::assertDispatched(DecisionEvaluated::class, static fn (DecisionEvaluated $event): bool => $event->action === $action
                && $event->resource                                                                                        === null
                && $event->reason                                                                                          === DecisionReason::RESOURCE_UNRESOLVED);
        }

        self::assertSame(DecisionStage::RESOURCE, Authorization::lastDecision()?->stage);

        Event::assertDispatchedTimes(AuthorizationFailed::class, 1);
        Event::assertDispatched(AuthorizationFailed::class, static fn (AuthorizationFailed $event): bool => $event->action === self::ACTION
            && $event->resource                                                                                            === null
            && $event->keys                                                                                                === []
            && $event->subject !== null
            && $event->reason === DecisionReason::RESOURCE_UNRESOLVED);
    }
}
