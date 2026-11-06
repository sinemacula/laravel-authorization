<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Contracts\Translation\Translator;
use Illuminate\Database\Eloquent\Relations\Relation;
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
use SineMacula\Laravel\Authorization\Http\Middleware\AbstractAuthorizationMiddleware;
use SineMacula\Laravel\Authorization\Http\Middleware\AuthorizeAction;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\ChecksAccess;
use Tests\Feature\Stubs\FixedResourceTenantResolver;
use Tests\Feature\Stubs\StubIdentity;
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

    /** @var array<string, class-string> The morph map before the test. */
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

        $identity = StubIdentity::create(['id' => 'author']);
        self::attachStatement($identity, 'allow', [self::ACTION], ['post:post-1']);

        $this->actAs($identity);

        $this->getJson('/posts/post-1')->assertOk();
        $this->getJson('/posts/post-2')->assertForbidden()->assertJson(['message' => 'This action is unauthorized.']);

        $this->withoutExceptionHandling();

        $denial = self::denialOf(fn () => $this->get('/posts/post-2'));

        self::assertSame(DecisionReason::NO_MATCH, $denial->getReason());
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
        $identity = StubIdentity::create(['id' => 'reader']);
        self::attachStatement($identity, 'allow', [self::ACTION], ['report-7']);

        $this->actAs($identity);

        $this->getJson('/reports/report-7')->assertOk();
        $this->getJson('/reports/report-8')->assertForbidden();
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
        $this->actAs(StubIdentity::create(['id' => 'drafter']));

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
        $this->actAs(StubIdentity::create(['id' => 'misrouted']));

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
        $this->registerPermissionGates();

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
        $this->actAs(StubIdentity::create(['id' => 'francophone']));

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
        $everything = StubIdentity::create(['id' => 'everything']);
        $scoped     = StubIdentity::create(['id' => 'scoped']);

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
        $identity = StubIdentity::create(['id' => 'lister']);
        self::attachStatement($identity, 'allow', [self::ACTION], ['post-1']);

        $this->actAs($identity);

        $this->getJson('/listed/post-1')->assertOk();
        $this->getJson('/listed/post-2')->assertForbidden();
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
        $this->registerPermissionGates();

        $post      = StubTenant::create(['id' => 'post-1']);
        $held      = self::identityHolding(permissions: [self::ACTION]);
        $denied    = self::identityHolding(permissions: [self::ACTION]);
        $elsewhere = StubIdentity::create(['id' => 'elsewhere']);

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
        $this->actAs(StubIdentity::create(['id' => 'outsider']));

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
                && $event->decision->reason                                                                                === DecisionReason::RESOURCE_UNRESOLVED
                && $event->decision->stage                                                                                 === DecisionStage::RESOURCE);
        }

        Event::assertDispatchedTimes(AuthorizationFailed::class, 1);
        Event::assertDispatched(AuthorizationFailed::class, static fn (AuthorizationFailed $event): bool => $event->action === self::ACTION
            && $event->resource                                                                                            === null
            && $event->context                                                                                             === []
            && $event->principal instanceof StubIdentity
            && $event->decision->reason === DecisionReason::RESOURCE_UNRESOLVED);
    }
}
