<?php

declare(strict_types = 1);

namespace Tests\Feature\SubjectScope;

use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Context\CheckContextFactory;
use SineMacula\Laravel\Authorization\Evaluation\CheckInput;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Events\AuthorizationFailed;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Authorization\Exceptions\AttributeProviderFailed;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\AuthorizationScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use Tests\Concerns\ScopesQueries;
use Tests\Feature\Stubs\Enums\PermissionEnum;
use Tests\Feature\Stubs\FailingResourceAttributes;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubTenant;
use Tests\Fixtures\QueryScoping\ScopedPost;
use Tests\TestCase;

/**
 * Feature tests for a manager from `for()` of a `Subject` naming a tenant or an
 * application (N109): every check through it is decided there, its grants and
 * the ambient scope both, as `AuthorizationScope::within()` around `for()` of
 * the subject in that scope decides it, with the request's scope restored
 * afterwards, even when the check throws.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(AuthorizationManager::class)]
final class AuthorizationManagerTest extends TestCase
{
    use ScopesQueries;

    /** @var string The action held in the first tenant alone. */
    private const string CREATE = 'posts:create';

    /** @var string The action held platform-wide on the admin application alone. */
    private const string DELETE = 'posts:delete';

    /** @var \Tests\Feature\Stubs\StubTenant The tenant the subject holds its grant in. */
    private StubTenant $first;

    /** @var \Tests\Feature\Stubs\StubTenant The tenant the request is in. */
    private StubTenant $second;

    /** @var \Tests\Feature\Stubs\StubIdentity The subject the checks are about. */
    private StubIdentity $user;

    /**
     * Grant the user the first action in the first tenant and the second
     * platform-wide on the admin application, and resolve the request in the
     * second tenant on the web application, about someone else.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        config(['authorization.permission_enums' => [PermissionEnum::class]]);

        $this->first  = StubTenant::query()->create(['id' => 'tenant-a', 'name' => 'A']);
        $this->second = StubTenant::query()->create(['id' => 'tenant-b', 'name' => 'B']);
        $this->user   = StubIdentity::create(['id' => 'user-1']);

        $this->user->givePermission(Permission::create(['name' => self::CREATE]), null, $this->first);
        $this->user->givePermission(Permission::create(['name' => self::DELETE]), null, null, true, 'admin');

        $this->resolveRequest(StubIdentity::create(['id' => 'request-user']), $this->second, 'web');
    }

    /**
     * A subject in the first tenant is decided on that tenant's grants while
     * the request is in the second, the decision made there, and one in the
     * second is refused; the request's tenant is back in place afterwards.
     *
     * @return void
     */
    public function testASubjectInATenantDecidesOnThatTenantsGrants(): void
    {
        self::assertTrue(Authorization::for($this->subject($this->first))->can(self::CREATE));
        self::assertSame(['tenant-a', null], self::provenance());
        self::assertFalse(Authorization::for($this->subject($this->second))->can(self::CREATE));
        self::assertSame(['tenant-b', null], self::provenance());
        self::assertSame([$this->second->getMorphClass(), 'tenant-b'], TenantScope::currentTenant());
        self::assertSame('web', TenantScope::currentApplication());
    }

    /**
     * A subject on an application is decided on that application's grants, at
     * the platform when it names no tenant, while the request is on another
     * application in a tenant.
     *
     * @return void
     */
    public function testASubjectOnAnApplicationDecidesOnThatApplicationsGrants(): void
    {
        self::assertTrue(Authorization::for($this->subject(null, 'admin'))->can(self::DELETE));
        self::assertSame([null, 'admin'], self::provenance());
        self::assertFalse(Authorization::for($this->subject(null, 'web'))->can(self::DELETE));
        self::assertFalse(Authorization::for($this->subject($this->first, 'web'))->can(self::DELETE));
        self::assertTrue(Authorization::for($this->subject($this->first, 'admin'))->can(self::DELETE));
        self::assertSame(['tenant-a', 'admin'], self::provenance());
        self::assertSame('web', TenantScope::currentApplication());
    }

    /**
     * A subject naming no tenant and no application, and a model, are decided
     * in the request's tenant and application, as before.
     *
     * @return void
     */
    public function testASubjectNamingNeitherUsesTheRequestsScope(): void
    {
        self::assertFalse(Authorization::for($this->subject())->can(self::CREATE));
        self::assertFalse(Authorization::for($this->user)->can(self::CREATE));
        self::assertSame(['tenant-b', 'web'], self::provenance());

        $this->resolveRequest(StubIdentity::create(['id' => 'request-user-2']), $this->first, 'admin');

        self::assertTrue(Authorization::for($this->subject())->can(self::CREATE));
        self::assertTrue(Authorization::for($this->user)->can(self::DELETE));
        self::assertSame(['tenant-a', 'admin'], self::provenance());
    }

    /**
     * Each subject is decided as `AuthorizationScope::within()` around `for()`
     * of the subject in its own scope decides it, so wrapping the call gives
     * the same decision, made in the same scope.
     *
     * @return void
     */
    public function testTheDecisionIsTheOneTheWithinFormMakes(): void
    {
        $cases = [
            [$this->first, null],
            [$this->second, null],
            [null, 'admin'],
            [$this->first, 'admin'],
            [null, 'web'],
        ];

        foreach ($cases as [$tenant, $application]) {
            $scope   = $tenant === null ? AuthorizationScope::platform($application) : AuthorizationScope::tenant($tenant, $application);
            $subject = $this->subject($tenant, $application);

            foreach ([self::CREATE, self::DELETE] as $action) {
                $within      = $scope->within(static fn (): Decision => Authorization::for($scope->subjectIn($subject))->check($action));
                $withinScope = self::provenance();
                $direct      = Authorization::for($subject)->check($action);
                $wrapped     = $scope->within(static fn (): Decision => Authorization::for($subject)->check($action));
                $message     = $action . ' in ' . ($tenant === null ? 'platform' : $tenant->getMorphClass()) . ' on ' . ($application ?? 'none');
                $directScope = self::provenance();

                self::assertSame([$within->effect, $within->reason], [$direct->effect, $direct->reason], $message);
                self::assertSame([$within->effect, $within->reason], [$wrapped->effect, $wrapped->reason], $message);
                self::assertSame($withinScope, $directScope, $message);
            }
        }
    }

    /**
     * Every method of the manager decides in the subject's scope: the single
     * checks, the bulk checks, the explanation, the listing in the subject's
     * scope and a query scoped through the manager.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException
     */
    public function testEveryMethodDecidesInTheSubjectsScope(): void
    {
        ScopedPost::query()->create(['title' => 'one']);

        $inFirst  = Authorization::for($this->subject($this->first));
        $inSecond = Authorization::for($this->subject($this->second));

        self::assertTrue($inFirst->check(self::CREATE)->isAllowed());
        self::assertFalse($inFirst->cannot(self::CREATE));
        self::assertTrue($inFirst->any([self::DELETE, self::CREATE]));
        self::assertTrue($inFirst->all([self::CREATE]));
        self::assertSame(['a' => true], \array_map(static fn (Decision $decision): bool => $decision->isAllowed(), $inFirst->checkMany(['a' => new CheckInput(self::CREATE)])));
        self::assertSame(['x' => true], $inFirst->canEach(self::CREATE, ['x' => null]));
        self::assertSame(['x' => null], $inFirst->filterAuthorized(self::CREATE, ['x' => null]));
        self::assertTrue($inFirst->explain(self::CREATE)->isAllowed());
        self::assertSame(['tenant-a', null], self::provenance());
        self::assertSame([self::CREATE], $inFirst->permissionsFor(null, AuthorizationScope::tenant($this->first)));
        self::assertSame(['one'], self::titles($inFirst));

        $inFirst->authorize(self::CREATE);

        self::assertFalse($inSecond->check(self::CREATE)->isAllowed());
        self::assertTrue($inSecond->cannot(self::CREATE));
        self::assertFalse($inSecond->any([self::DELETE, self::CREATE]));
        self::assertFalse($inSecond->all([self::CREATE]));
        self::assertSame(['a' => false], \array_map(static fn (Decision $decision): bool => $decision->isAllowed(), $inSecond->checkMany(['a' => new CheckInput(self::CREATE)])));
        self::assertSame(['x' => false], $inSecond->canEach(self::CREATE, ['x' => null]));
        self::assertSame([], $inSecond->filterAuthorized(self::CREATE, ['x' => null]));
        self::assertFalse($inSecond->explain(self::CREATE)->isAllowed());
        self::assertSame([], $inSecond->permissionsFor(null, AuthorizationScope::tenant($this->second)));
        self::assertSame([], self::titles($inSecond));
    }

    /**
     * A listing is made in the scope it is given, which wins over the
     * subject's, as it does inside `AuthorizationScope::within()`.
     *
     * @return void
     */
    public function testAListingIsMadeInTheScopeItIsGiven(): void
    {
        $inFirst = Authorization::for($this->subject($this->first));
        $scope   = AuthorizationScope::tenant($this->second);

        self::assertSame([], $inFirst->permissionsFor(null, $scope));
        self::assertSame([], $scope->within(fn (): array => Authorization::for($scope->subjectIn($this->subject($this->first)))->permissionsFor(null, $scope)));
        self::assertSame([self::CREATE], Authorization::for($this->subject($this->second))->permissionsFor(null, AuthorizationScope::tenant($this->first)));
    }

    /**
     * A refusal is reported in the subject's scope, and so is one whose own
     * decision a listener forgot before it was reported.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException
     */
    public function testARefusalIsReportedInTheSubjectsScope(): void
    {
        Event::fake([AuthorizationFailed::class]);

        $this->resolveRequest(StubIdentity::create(['id' => 'request-user-2']), $this->second, 'web');

        $inFirst = Authorization::for($this->subject($this->first));

        try {
            $inFirst->authorize(self::DELETE);

            self::fail('The check is refused.');
        } catch (AuthorizationException $exception) {
            self::assertSame(DecisionReason::NO_MATCH, $exception->getDecision()?->reason);
        }

        // A listener forgets each decision as it is reported, so the refusal is
        // reported with the provenance of the scope the check is made in.
        Event::listen(DecisionEvaluated::class, static function (): void {
            Authorization::forgetLastDecision();
        });

        try {
            $inFirst->authorize(self::DELETE);

            self::fail('The check is refused.');
        } catch (AuthorizationException) {
            self::assertNull(Authorization::lastDecision());
        }

        $tenants = [];

        Event::assertDispatched(AuthorizationFailed::class, static function (AuthorizationFailed $event) use (&$tenants): bool {
            $tenants[] = $event->tenant?->id;

            return true;
        });

        self::assertSame(['tenant-a', 'tenant-a'], $tenants);
    }

    /**
     * A check that throws in the subject's scope leaves the request's tenant
     * and application in place, and the next check of the request is decided
     * there.
     *
     * @return void
     */
    public function testTheRequestsScopeIsRestoredAfterAnException(): void
    {
        $provider = new FailingResourceAttributes;

        $this->app?->instance(FailingResourceAttributes::class, $provider);
        config(['authorization.attributes.resources' => ['posts' => FailingResourceAttributes::class]]);

        $this->app?->forgetInstance(CheckContextFactory::class);
        $this->resolveRequest(StubIdentity::create(['id' => 'request-user-2']), $this->second, 'web');

        $policy = EvaluationPolicy::fromArray(['name' => 'status', 'statements' => [
            ['effect' => 'allow', 'actions' => [self::DELETE], 'conditions' => ['eq' => ['resource.status' => 'published']]],
        ]]);

        $resource = ResourceReference::record('posts', 'p1', Reference::of($this->first));
        $manager  = Authorization::for($this->subject($this->first))->withPolicies([$policy]);

        $calls = [
            static fn (): mixed => $manager->check(self::DELETE, $resource),
            static fn (): mixed => $manager->checkMany([new CheckInput(self::DELETE, $resource)]),
            static fn (): mixed => $manager->explain(self::DELETE, $resource),
        ];

        foreach ($calls as $call) {
            try {
                $call();

                self::fail('The check throws.');
            } catch (AttributeProviderFailed) {
                self::assertSame([$this->second->getMorphClass(), 'tenant-b'], TenantScope::currentTenant());
                self::assertSame('web', TenantScope::currentApplication());
            }
        }

        self::assertSame(3, $provider->calls);
        self::assertFalse(Authorization::for($this->user)->can(self::CREATE));
        self::assertSame(['tenant-b', 'web'], self::provenance());
    }

    /**
     * Return the user as a subject naming the tenant and the application.
     *
     * @param  \Tests\Feature\Stubs\StubTenant|null  $tenant
     * @param  string|null  $application
     * @return \SineMacula\Laravel\Authorization\Subject
     */
    private function subject(?StubTenant $tenant = null, ?string $application = null): Subject
    {
        return new Subject($this->user, $this->user, $tenant, $application);
    }

    /**
     * Return the tenant id and the application the last decision was made in.
     *
     * @return array{0: string|null, 1: string|null}
     */
    private static function provenance(): array
    {
        $provenance = Authorization::lastDecisionProvenance();

        return [$provenance?->tenant?->id, $provenance?->application];
    }

    /**
     * Return the titles of the posts the manager may take the first action on,
     * through `whereAuthorized()`.
     *
     * @param  \SineMacula\Laravel\Authorization\AuthorizationManager  $manager
     * @return list<string>
     */
    private static function titles(AuthorizationManager $manager): array
    {
        /** @var list<string> */
        return ScopedPost::query()->whereAuthorized(self::CREATE, [], $manager)->orderBy('id')->pluck('title')->all(); // @phpstan-ignore method.notFound
    }
}
