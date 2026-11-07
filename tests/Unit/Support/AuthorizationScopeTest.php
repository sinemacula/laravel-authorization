<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Cache\Resolution;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\AuthorizationScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResolvedTenant;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubSubjectResolver;
use Tests\Feature\Stubs\StubTenant;
use Tests\TestCase;

/**
 * Unit tests for `AuthorizationScope`, the scope `permissionsFor()` lists a
 * subject's actions in: its named constructors, its resource, and how it puts
 * its tenant and application in place of the request's and back.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(AuthorizationScope::class)]
final class AuthorizationScopeTest extends TestCase
{
    /**
     * The platform's scope names no tenant, the application given or none, and
     * no resource.
     *
     * @return void
     */
    public function testThePlatformNamesNoTenant(): void
    {
        $scope = AuthorizationScope::platform();

        self::assertNull($scope->tenant);
        self::assertNull($scope->application);
        self::assertNull($scope->resource);
        self::assertSame('admin', AuthorizationScope::platform('admin')->application);
    }

    /**
     * A tenant's scope normalises a model or an `AuthorizableTenant` to its
     * reference, keeps a reference as it is, and refuses a tenant without a
     * key.
     *
     * @return void
     */
    public function testATenantIsNormalisedToItsReference(): void
    {
        $tenant    = StubTenant::query()->create(['id' => 't1', 'name' => 't1']);
        $reference = new Reference('accounts', '7');

        self::assertEquals(new Reference($tenant->getMorphClass(), 't1'), AuthorizationScope::tenant($tenant)->tenant);
        self::assertSame($reference, AuthorizationScope::tenant($reference, 'admin')->tenant);
        self::assertSame('admin', AuthorizationScope::tenant($reference, 'admin')->application);
        self::assertNull(AuthorizationScope::tenant($tenant)->application);
        self::assertNull(AuthorizationScope::tenant($tenant)->resource);

        $this->expectException(InvalidTenantException::class);

        AuthorizationScope::tenant(new StubTenant);
    }

    /**
     * The current scope captures the request's tenant and application, as the
     * resolvers report them, and the platform with no application without a
     * subject.
     *
     * @return void
     */
    public function testTheCurrentScopeCapturesTheRequestsTenantAndApplication(): void
    {
        self::assertEquals(AuthorizationScope::platform(), AuthorizationScope::current());

        $tenant = StubTenant::query()->create(['id' => 't1', 'name' => 't1']);

        $this->resolve(new StubSubjectResolver(StubIdentity::create(['id' => 'user-1']), $tenant, 'admin'));

        $scope = AuthorizationScope::current();

        self::assertEquals(new Reference($tenant->getMorphClass(), 't1'), $scope->tenant);
        self::assertSame('admin', $scope->application);
        self::assertNull($scope->resource);
    }

    /**
     * A scope with a resource keeps the tenant and the application, and leaves
     * the scope it was made from as it was.
     *
     * @return void
     */
    public function testWithResourceKeepsTheTenantAndApplication(): void
    {
        $scope    = AuthorizationScope::tenant(new Reference('accounts', '7'), 'admin');
        $resource = ['posts', '1'];
        $named    = $scope->withResource($resource);

        self::assertNotSame($scope, $named);
        self::assertSame($resource, $named->resource);
        self::assertSame($scope->tenant, $named->tenant);
        self::assertSame('admin', $named->application);
        self::assertNull($scope->resource);
        self::assertNull($named->withResource(null)->resource);
    }

    /**
     * Within the scope, the tenant and application are the scope's, and the
     * request's are back afterwards.
     *
     * @return void
     */
    public function testWithinPutsTheScopeInPlaceAndRestoresTheRequests(): void
    {
        $request = StubTenant::query()->create(['id' => 't1', 'name' => 't1']);

        $this->resolve(new StubSubjectResolver(StubIdentity::create(['id' => 'user-1']), $request, 'web'));

        $scope = AuthorizationScope::tenant(new Reference('accounts', '7'), 'admin');

        self::assertSame([['accounts', '7'], 'admin'], $scope->within(static fn (): array => [TenantScope::currentTenant(), TenantScope::currentApplication()]));
        self::assertSame([[$request->getMorphClass(), 't1'], 'web'], [TenantScope::currentTenant(), TenantScope::currentApplication()]);
    }

    /**
     * The request's tenant and application are back once the callback run
     * within the scope throws, and what it throws is thrown.
     *
     * @return void
     */
    public function testTheRequestsScopeIsRestoredWhenTheCallbackThrows(): void
    {
        $request = StubTenant::query()->create(['id' => 't1', 'name' => 't1']);

        $this->resolve(new StubSubjectResolver(StubIdentity::create(['id' => 'user-1']), $request, 'web'));

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('failed');

        try {
            AuthorizationScope::platform()->within(self::failing(...));
        } finally {
            self::assertSame([[$request->getMorphClass(), 't1'], 'web'], [TenantScope::currentTenant(), TenantScope::currentApplication()]);
        }
    }

    /**
     * The subject in the scope keeps its model, identity, guard and session,
     * with the scope's tenant and application in place of its own; a guest
     * stays a guest.
     *
     * @return void
     */
    public function testTheSubjectInTheScopeKeepsItsIdentityGuardAndSession(): void
    {
        $user     = new StubIdentity;
        $identity = new StubIdentity;
        $scope    = AuthorizationScope::tenant(new Reference('accounts', '7'), 'admin');
        $subject  = $scope->subjectIn(new Subject($user, $identity, new Reference('accounts', '1'), 'web', 'api', 'session-1'));

        self::assertNotNull($subject);
        self::assertSame($user, $subject->subject);
        self::assertSame($identity, $subject->identity);
        self::assertSame($scope->tenant, $subject->tenant);
        self::assertSame('admin', $subject->application);
        self::assertSame('api', $subject->guard);
        self::assertSame('session-1', $subject->session);
        self::assertNull(AuthorizationScope::platform()->subjectIn(new Subject($user))?->tenant);
        self::assertNull($scope->subjectIn(null));
    }

    /**
     * A reference without a key is refused as a tenant, as a model without one
     * is, when the scope is made.
     *
     * @return void
     */
    public function testAReferenceWithoutAKeyIsRefused(): void
    {
        $this->expectException(InvalidTenantException::class);

        AuthorizationScope::tenant(new Reference('accounts', ''));
    }

    /**
     * A scope whose tenant and application are those in place is not applied
     * again, so the tenant the request holds stays as it is; one that differs
     * in its tenant, its tenant's type or its application is applied, and the
     * request's tenant is resolved again afterwards.
     *
     * @return void
     */
    public function testAScopeInPlaceIsNotAppliedAgain(): void
    {
        $request = StubTenant::query()->create(['id' => 't1', 'name' => 't1']);

        $this->resolve(new StubSubjectResolver(StubIdentity::create(['id' => 'user-1']), $request, 'web'));

        $held = $this->held();

        $inPlace = [
            AuthorizationScope::current(),
            AuthorizationScope::tenant($request, 'web'),
            AuthorizationScope::tenant(new Reference($request->getMorphClass(), 't1'), 'web'),
        ];

        foreach ($inPlace as $scope) {
            self::assertSame($held, $scope->within($this->held(...)));
            self::assertSame($held, $this->held());
        }

        $differing = [
            AuthorizationScope::tenant($request, 'admin'),
            AuthorizationScope::tenant($request),
            AuthorizationScope::tenant(new Reference($request->getMorphClass(), 't2'), 'web'),
            AuthorizationScope::tenant(new Reference('accounts', 't1'), 'web'),
            AuthorizationScope::platform('web'),
        ];

        foreach ($differing as $scope) {
            $held = $this->held();

            self::assertNotSame($held, $scope->within($this->held(...)));
            self::assertNotSame($held, $this->held());
        }

        $this->resolve(new StubSubjectResolver(StubIdentity::create(['id' => 'user-2'])));

        $held = $this->held();

        self::assertSame($held, AuthorizationScope::platform()->within($this->held(...)));
    }

    /**
     * Checks decided just below the request's tenant are not in the scope of
     * that tenant, so applying it decides in the tenant again.
     *
     * @return void
     */
    public function testAScopeIsAppliedOverChecksDecidedBelowItsTenant(): void
    {
        $request = StubTenant::query()->create(['id' => 't1', 'name' => 't1']);

        $this->resolve(new StubSubjectResolver(StubIdentity::create(['id' => 'user-1']), $request, 'web'));

        $isBelow = TenantScope::within($request, 'web', static fn (): array => [
            TenantScope::isBelowTenant(),
            AuthorizationScope::current()->within(static fn (): bool => TenantScope::isBelowTenant()),
        ], true);

        self::assertSame([true, false], $isBelow);
    }

    /**
     * A request whose tenant cannot be read is in no scope, so a scope is
     * applied over it.
     *
     * @return void
     */
    public function testAScopeIsAppliedOverATenantThatCannotBeRead(): void
    {
        $this->resolve(new StubSubjectResolver(StubIdentity::create(['id' => 'user-1']), new StubTenant, 'web'));

        self::assertSame([null, 'admin'], AuthorizationScope::platform('admin')->within(static fn (): array => [TenantScope::currentTenant(), TenantScope::currentApplication()]));
    }

    /**
     * What the resolution cache held for the request's scope is back once a
     * callback run in another scope returns, so it is not resolved again, and a
     * scope in place leaves it as it is.
     *
     * @return void
     */
    public function testWhatTheCacheHeldForTheRequestIsKept(): void
    {
        $request = StubTenant::query()->create(['id' => 't1', 'name' => 't1']);
        $cache   = new ResolutionCache;

        /** @var \ArrayObject<int, string|null> $read */
        $read = new \ArrayObject;

        $this->resolve(new StubSubjectResolver(StubIdentity::create(['id' => 'user-1']), $request, 'web'));
        $this->app?->instance(ResolutionCache::class, $cache);

        $remember = static fn (): array => $cache->rememberPermissions(new Reference('users', '1'), static function () use ($read): Resolution {
            $read[] = TenantScope::currentApplication();

            return new Resolution(['posts:read']);
        });

        $remember();

        AuthorizationScope::platform('admin')->within($remember);
        AuthorizationScope::current()->within($remember);

        $remember();

        self::assertSame(['web', 'admin'], $read->getArrayCopy());
    }

    /**
     * Fail, as a callback run within a scope may.
     *
     * @return mixed
     *
     * @throws \RuntimeException
     */
    private static function failing(): mixed
    {
        throw new \RuntimeException('failed');
    }

    /**
     * Return the tenant held for the request, or for the scope in place.
     *
     * @return \SineMacula\Laravel\Authorization\Support\ResolvedTenant
     */
    private function held(): ResolvedTenant
    {
        /** @var \SineMacula\Laravel\Authorization\Support\ResolvedTenant */
        return $this->app?->make(ResolvedTenant::class);
    }

    /**
     * Resolve the request through the resolver, forgetting the tenant held.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\SubjectResolver  $resolver
     * @return void
     */
    private function resolve(SubjectResolver $resolver): void
    {
        $this->app?->instance(SubjectResolver::class, $resolver);
        $this->app?->forgetInstance(ResolvedTenant::class);
    }
}
