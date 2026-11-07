<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use PHPUnit\Framework\Attributes\CoversClass;
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
