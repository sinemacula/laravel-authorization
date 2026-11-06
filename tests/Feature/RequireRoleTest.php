<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Http\Response;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\TestWith;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Exceptions\InvalidCheckArgumentException;
use SineMacula\Laravel\Authorization\Http\Middleware\AbstractAuthorizationMiddleware;
use SineMacula\Laravel\Authorization\Http\Middleware\RequireRole;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Subject;
use Tests\Concerns\ChecksAccess;
use Tests\Feature\Stubs\FixedSubjectResolver;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubSecondIdentity;
use Tests\Feature\Stubs\StubTenant;
use Tests\Feature\Stubs\SuspendableIdentity;
use Tests\TestCase;

/**
 * Feature coverage for the `role` route middleware, which checks role
 * membership on the subject rather than deciding an action.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(RequireRole::class)]
#[CoversClass(AbstractAuthorizationMiddleware::class)]
final class RequireRoleTest extends TestCase
{
    use ChecksAccess;

    /**
     * A role the subject's identity holds admits the request; a subject or
     * identity that is inactive is denied as `subject_inactive`.
     *
     * @return void
     *
     * @throws \Illuminate\Auth\AuthenticationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException
     */
    public function testTheIdentitysRolesCountUnlessInactive(): void
    {
        $principal = SuspendableIdentity::create(['id' => 'account-1']);
        $identity  = StubSecondIdentity::create(['id' => 'person-1']);

        $identity->assignRole(Role::create(['name' => 'staff']));
        $this->app?->instance(SubjectResolver::class, new FixedSubjectResolver(new Subject($principal, $identity)));

        self::assertSame(200, $this->handle('staff')->getStatusCode());

        $principal->suspended = true;

        self::assertSame(DecisionReason::SUBJECT_INACTIVE, self::denialOf(fn (): Response => $this->handle('staff'))->getReason());
    }

    /**
     * A held role admits the request.
     *
     * @return void
     *
     * @throws \Illuminate\Auth\AuthenticationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException
     */
    public function testHeldRoleIsAllowed(): void
    {
        $this->actAs(self::identityHolding(roles: ['admin']));

        self::assertSame(200, $this->handle('admin')->getStatusCode());
    }

    /**
     * A missing role denies the request with the generic translated message.
     *
     * @return void
     */
    public function testMissingRoleIsDenied(): void
    {
        $this->actAs(self::identityHolding(roles: ['editor']));

        $denial = self::denialOf(fn (): Response => $this->handle('admin'));

        self::assertSame(DecisionReason::NO_MATCH, $denial->getReason());
        self::assertSame(403, $denial->getCode());
        self::assertSame('This action is unauthorized.', $denial->getMessage());
    }

    /**
     * Any one held role of a `|` list admits the request, whatever its
     * position, with whitespace around the names and empty names ignored.
     *
     * @param  string  $list
     * @return void
     *
     * @throws \Illuminate\Auth\AuthenticationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException
     */
    #[TestWith(['admin|editor'])]
    #[TestWith(['editor|admin'])]
    #[TestWith([' admin | | editor '])]
    public function testAnyHeldRoleOfAListIsEnough(string $list): void
    {
        $this->actAs(self::identityHolding(roles: ['editor']));

        self::assertSame(200, $this->handle($list)->getStatusCode());
    }

    /**
     * A list that names no role is a mistake in the route, and is refused.
     *
     * @param  string  $list
     * @return void
     *
     * @throws \Illuminate\Auth\AuthenticationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException
     */
    #[TestWith([''])]
    #[TestWith([' | '])]
    public function testAListNamingNoRoleIsRefused(string $list): void
    {
        $this->actAs(self::identityHolding(roles: ['admin']));

        $this->expectException(InvalidCheckArgumentException::class);
        $this->expectExceptionMessage(RequireRole::class . ' names nothing to check. List one or more names, separated by \'|\'.');

        $this->handle($list);
    }

    /**
     * A role is not an action: a policy denying an action of the same name does
     * not deny the role's holder, and one allowing it does not admit a subject
     * without the role.
     *
     * @return void
     *
     * @throws \Illuminate\Auth\AuthenticationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException
     */
    public function testPoliciesDoNotDecideARole(): void
    {
        $holder = self::identityHolding(roles: ['admin']);
        $other  = StubIdentity::create(['id' => 'other']);

        self::attachStatement($holder, 'deny', ['*']);
        self::attachStatement($other, 'allow', ['*']);

        $this->actAs($holder);
        self::assertSame(200, $this->handle('admin')->getStatusCode());

        $this->actAs($other);
        self::assertFalse($this->admits(RequireRole::class, self::request(), 'admin'));
    }

    /**
     * A subject that cannot hold roles holds none, and is denied.
     *
     * @return void
     */
    public function testASubjectWithoutRolesIsDenied(): void
    {
        $this->actAs(new \stdClass);

        self::assertSame(DecisionReason::NO_MATCH, self::denialOf(fn (): Response => $this->handle('admin'))->getReason());
    }

    /**
     * A guard limits the check to the roles of that guard and the
     * guard-agnostic ones.
     *
     * @return void
     *
     * @throws \Illuminate\Auth\AuthenticationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException
     */
    public function testAGuardLimitsTheRolesThatCount(): void
    {
        config(['auth.guards.api' => ['driver' => 'session', 'provider' => 'users']]);

        $identity = StubIdentity::create(['id' => 'guarded']);
        $identity->assignRole(Role::create(['name' => 'admin', 'guard' => 'api']));
        $identity->assignRole(Role::create(['name' => 'auditor', 'guard' => null]));

        $this->actAs($identity);

        self::assertSame(200, $this->handle('admin', 'api')->getStatusCode());
        self::assertSame(200, $this->handle('auditor', 'web')->getStatusCode());
        self::assertSame(200, $this->handle('admin')->getStatusCode());
        self::assertFalse($this->admits(RequireRole::class, self::request(), 'admin', 'web'));
    }

    /**
     * A guard that is not an authentication guard is refused, even without a
     * subject, so a comma-separated list is never read as a role and a guard.
     *
     * @return void
     *
     * @throws \Illuminate\Auth\AuthenticationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException
     */
    public function testAnUnknownGuardIsRefused(): void
    {
        $this->actAs(null);

        $this->expectException(InvalidCheckArgumentException::class);
        $this->expectExceptionMessage('\'editor\' is not an authentication guard. A role check takes the roles, separated by \'|\', then an optional guard.');

        $this->handle('admin', 'editor');
    }

    /**
     * A bare guard that is also the name of a role, of any tenant, is refused,
     * since `role:editor,admin` may list a second role; with the prefix it is
     * the guard.
     *
     * @return void
     *
     * @throws \Illuminate\Auth\AuthenticationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException
     */
    public function testAGuardNamingARoleIsRefusedUnlessPrefixed(): void
    {
        config(['auth.guards.admin' => ['driver' => 'session', 'provider' => 'users']]);

        $tenant   = StubTenant::create(['id' => 'tenant-a', 'name' => 'A']);
        $identity = StubIdentity::create(['id' => 'editor']);
        $identity->assignRole(Role::create(['name' => 'editor', 'guard' => 'admin']));

        Role::create(['name' => 'admin', 'guard' => 'web', 'tenant_type' => $tenant->getMorphClass(), 'tenant_id' => 'tenant-a']);

        $this->actAs($identity);

        self::assertSame(200, $this->handle('editor', 'guard=admin')->getStatusCode());
        self::assertFalse($this->admits(RequireRole::class, self::request(), 'editor', 'guard=web'));

        $this->expectException(InvalidCheckArgumentException::class);
        $this->expectExceptionMessage('\'admin\' is both an authentication guard and a role. Separate several roles with \'|\', or write the guard as \'guard=admin\'.');

        $this->handle('editor', 'admin');
    }

    /**
     * The check sees the roles of the subject's tenant and the platform's, as
     * `hasRole()` does, and not another tenant's.
     *
     * @return void
     *
     * @throws \Illuminate\Auth\AuthenticationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException
     */
    public function testTheSubjectsTenantScopesTheRoles(): void
    {
        $tenantA  = StubTenant::create(['id' => 'tenant-a', 'name' => 'A']);
        $tenantB  = StubTenant::create(['id' => 'tenant-b', 'name' => 'B']);
        $identity = StubIdentity::create(['id' => 'manager-1']);

        $this->actingAsIdentity($identity, $tenantA);
        $identity->assignRole(Role::create(['name' => 'manager', 'guard' => 'web', 'tenant_type' => $tenantA->getMorphClass(), 'tenant_id' => 'tenant-a']));

        self::assertSame(200, $this->handle('manager')->getStatusCode());

        $this->actingAsIdentity(StubIdentity::query()->findOrFail('manager-1'), $tenantB);
        self::assertFalse($this->admits(RequireRole::class, self::request(), 'manager'));
    }

    /**
     * A request without a subject is unauthenticated.
     *
     * @return void
     *
     * @throws \Illuminate\Auth\AuthenticationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException
     */
    public function testARequestWithoutASubjectIsUnauthenticated(): void
    {
        $this->actAs(null);

        $this->expectException(AuthenticationException::class);

        $this->handle('admin');
    }

    /**
     * Run the middleware with the given arguments.
     *
     * @param  string  ...$arguments
     * @return \Illuminate\Http\Response
     *
     * @throws \Illuminate\Auth\AuthenticationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException
     */
    private function handle(string ...$arguments): Response
    {
        return $this->runMiddleware(RequireRole::class, self::request(), ...$arguments);
    }
}
