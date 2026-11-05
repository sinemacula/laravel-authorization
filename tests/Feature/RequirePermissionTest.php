<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Gate;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\TestWith;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Events\AuthorizationFailed;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Authorization\Exceptions\InvalidCheckArgumentException;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Http\Middleware\AbstractAuthorizationMiddleware;
use SineMacula\Laravel\Authorization\Http\Middleware\RequirePermission;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use Tests\Concerns\ChecksAccess;
use Tests\Feature\Stubs\RolesOnlyPrincipal;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature coverage for the `permission` route middleware, which decides each
 * listed action through the authorization manager's full decision.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(RequirePermission::class)]
#[CoversClass(AbstractAuthorizationMiddleware::class)]
final class RequirePermissionTest extends TestCase
{
    use ChecksAccess;

    /** @var string Action reused across the scenarios. */
    private const string ACTION = 'posts:update';

    /**
     * A held permission admits the request.
     *
     * @return void
     */
    public function testHeldPermissionIsAllowed(): void
    {
        $this->actAs(self::identityHolding(permissions: [self::ACTION]));

        self::assertSame(200, $this->handle(self::ACTION)->getStatusCode());
    }

    /**
     * A permission held through a role admits the request.
     *
     * @return void
     */
    public function testPermissionHeldThroughARoleIsAllowed(): void
    {
        $role = Role::create(['name' => 'editor', 'guard' => 'web']);
        $role->givePermission(Permission::create(['name' => self::ACTION, 'guard' => 'web']));

        $identity = StubIdentity::create(['id' => 'editor-1']);
        $identity->assignRole($role);

        $this->actAs($identity);

        self::assertSame(200, $this->handle(self::ACTION)->getStatusCode());
    }

    /**
     * An explicit deny wins over a held permission, and the denial carries the
     * deny's reason code and the translated message.
     *
     * @return void
     */
    public function testExplicitDenyWinsOverAHeldPermission(): void
    {
        $identity = self::identityHolding(permissions: [self::ACTION]);
        self::attachStatement($identity, 'deny', [self::ACTION]);

        $this->actAs($identity);

        $denial = self::denialOf(fn (): Response => $this->handle(self::ACTION));

        self::assertSame(DecisionReason::EXPLICIT_DENY, $denial->getReason());
        self::assertSame(403, $denial->getCode());
        self::assertSame('This action is unauthorized.', $denial->getMessage());
    }

    /**
     * A policy allow admits the request without the permission being held.
     *
     * @return void
     */
    public function testPolicyAllowWithoutAHeldPermissionIsAllowed(): void
    {
        $identity = self::identityHolding();
        self::attachStatement($identity, 'allow', [self::ACTION]);

        $this->actAs($identity);

        self::assertSame(200, $this->handle(self::ACTION)->getStatusCode());
    }

    /**
     * Without a grant or a policy the request is implicitly denied.
     *
     * @return void
     */
    public function testMissingPermissionIsImplicitlyDenied(): void
    {
        $this->actAs(self::identityHolding());

        $denial = self::denialOf(fn (): Response => $this->handle(self::ACTION));

        self::assertSame(DecisionReason::IMPLICIT_DENY, $denial->getReason());
    }

    /**
     * A subject that cannot hold permissions is decided like any other: here a
     * policy the resolver gives every subject allows it one action.
     *
     * @return void
     */
    public function testAnySubjectTheManagerDecidesAboutIsAccepted(): void
    {
        $this->allowEverySubject([self::ACTION]);
        $this->actAs(new RolesOnlyPrincipal);

        self::assertSame(200, $this->handle(self::ACTION)->getStatusCode());
        self::assertSame(DecisionReason::IMPLICIT_DENY, self::denialOf(fn (): Response => $this->handle('posts:delete'))->getReason());
    }

    /**
     * Any one allowed action of a `|` list admits the request, whatever its
     * position, with whitespace around the names and empty names ignored.
     *
     * @param  string  $list
     * @return void
     */
    #[TestWith(['posts:delete|posts:update'])]
    #[TestWith(['posts:update|posts:delete'])]
    #[TestWith([' posts:delete | | posts:update '])]
    public function testAnyAllowedActionOfAListIsEnough(string $list): void
    {
        $this->actAs(self::identityHolding(permissions: [self::ACTION]));

        self::assertSame(200, $this->handle($list)->getStatusCode());
    }

    /**
     * The first allowed action admits the request without deciding the rest.
     *
     * @return void
     */
    public function testTheFirstAllowedActionEndsTheChecks(): void
    {
        $this->actAs(self::identityHolding(permissions: [self::ACTION]));

        Event::fake([DecisionEvaluated::class]);

        $this->handle(self::ACTION . '|posts:delete');

        Event::assertDispatchedTimes(DecisionEvaluated::class, 1);
    }

    /**
     * When no listed action is allowed, the denial is the last action's: its
     * reason code, its recorded decision and its `AuthorizationFailed` event.
     *
     * @return void
     */
    public function testADeniedListReportsTheLastActionsDecision(): void
    {
        $identity = self::identityHolding();
        self::attachStatement($identity, 'deny', ['posts:delete']);

        $this->actAs($identity);

        Event::fake([AuthorizationFailed::class]);

        $denial = self::denialOf(fn (): Response => $this->handle(self::ACTION . '|posts:delete'));

        self::assertSame(DecisionReason::EXPLICIT_DENY, $denial->getReason());
        self::assertSame(DecisionReason::EXPLICIT_DENY, Authorization::lastDecision()?->reason);
        Event::assertDispatchedTimes(AuthorizationFailed::class, 1);
        Event::assertDispatched(AuthorizationFailed::class, static fn (AuthorizationFailed $event): bool => $event->action === 'posts:delete');
    }

    /**
     * A list that names no action is a mistake in the route, and is refused
     * rather than decided, even when every action would be allowed.
     *
     * @param  string  $list
     * @return void
     */
    #[TestWith([''])]
    #[TestWith([' | '])]
    public function testAListNamingNoActionIsRefused(string $list): void
    {
        $this->allowEverySubject(['*']);
        $this->actAs(self::identityHolding());

        $this->expectException(InvalidCheckArgumentException::class);
        $this->expectExceptionMessage(RequirePermission::class . ' names nothing to check. List one or more names, separated by \'|\'.');

        $this->handle($list);
    }

    /**
     * A guard argument is refused, even without a subject, since no guard
     * changes the decision.
     *
     * @return void
     */
    public function testAGuardArgumentIsRefused(): void
    {
        $this->actAs(null);

        $this->expectException(InvalidCheckArgumentException::class);
        $this->expectExceptionMessage('A permission check takes no guard: it is decided on the full authorization decision, which no guard changes. Remove the guard \'web\'.');

        $this->handle(self::ACTION, 'web');
    }

    /**
     * The middleware and the Gate answer the same for a held permission, an
     * explicit deny over one, a policy allow without one, and no grant.
     *
     * @return void
     */
    public function testTheMiddlewareAndTheGateAgree(): void
    {
        $this->registerPermissionGates();

        $held   = self::identityHolding(permissions: ['posts:create']);
        $denied = self::identityHolding(permissions: ['posts:delete']);
        $policy = StubIdentity::create(['id' => 'policy-only']);

        self::attachStatement($denied, 'deny', ['posts:delete']);
        self::attachStatement($policy, 'allow', ['posts:delete']);

        $cases = [[$held, 'posts:create', true], [$denied, 'posts:delete', false], [$policy, 'posts:delete', true], [$policy, 'posts:create', false]];

        foreach ($cases as [$identity, $action, $expected]) {
            $this->actAs($identity);

            self::assertSame($expected, Gate::forUser($identity)->allows($action), "The Gate answered wrongly on {$action}.");
            self::assertSame($expected, $this->admits(RequirePermission::class, self::request(), $action), "The middleware disagrees with the Gate on {$action}.");
        }
    }

    /**
     * A request without a subject is unauthenticated.
     *
     * @return void
     */
    public function testARequestWithoutASubjectIsUnauthenticated(): void
    {
        $this->actAs(null);

        $this->expectException(AuthenticationException::class);

        $this->handle(self::ACTION);
    }

    /**
     * Run the middleware with the given arguments.
     *
     * @param  string  ...$arguments
     * @return \Illuminate\Http\Response
     */
    private function handle(string ...$arguments): Response
    {
        return $this->runMiddleware(RequirePermission::class, self::request(), ...$arguments);
    }
}
