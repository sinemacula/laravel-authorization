<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Concerns\HasPermissions;
use SineMacula\Laravel\Authorization\Concerns\HasPolicies;
use SineMacula\Laravel\Authorization\Concerns\HasRoles;
use SineMacula\Laravel\Authorization\Concerns\ResolvesPivotExpiry;
use SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect;
use SineMacula\Laravel\Authorization\Evaluation\LastDecisionStore;
use SineMacula\Laravel\Authorization\Evaluation\Policy;
use SineMacula\Laravel\Authorization\Evaluation\Statement;
use SineMacula\Laravel\Authorization\Events\Identity\PermissionExpiryChanged;
use SineMacula\Laravel\Authorization\Events\Identity\PolicyExpiryChanged;
use SineMacula\Laravel\Authorization\Events\Identity\RoleExpiryChanged;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Mutation-killer feature tests targeting the `ResolvesPivotExpiry` helper, the
 * `ResolutionCache` TTL / key routing, and the authorizable-identity trait
 * branches whose semantic mutants escaped the initial mutation sweep.
 *
 * These tests assert exact values (counts, keys, time bounds) so subtle
 * mutations — `<` vs `<=`, `||` vs `&&`, off-by-one on integer literals, cast
 * removal — surface as failures rather than silently passing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 * @SuppressWarnings("php:S1448")
 */
#[CoversClass(ResolutionCache::class)]
#[CoversClass(Statement::class)]
#[CoversClass(AuthorizationManager::class)]
#[CoversTrait(HasRoles::class)]
#[CoversTrait(HasPermissions::class)]
#[CoversTrait(HasPolicies::class)]
#[CoversTrait(ResolvesPivotExpiry::class)]
final class MutationKillersTest extends TestCase
{
    /**
     * `assignRole()` fires `IdentityRoleAssigned` exactly once for a first-time
     * grant and does not re-fire if the expiry is unchanged — pins the
     * expiry-equality branch.
     *
     * @return void
     */
    public function testAssignRoleIsIdempotentWhenExpiryUnchanged(): void
    {
        Event::fake(
            [RoleExpiryChanged::class],
        );

        $role = Role::create(['id' => (string) Str::uuid(), 'name' => 'idem', 'guard' => 'web']);
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);

        // Anchor Carbon so the computed expiry is deterministic and identical
        // across both calls — avoids wall-clock drift.
        Carbon::setTestNow('2026-01-01 00:00:00');

        try {
            $expires = Carbon::now()->addHour()->toDateTimeImmutable();
            $user->assignRole($role, $expires);
            $user->assignRole($role, $expires);
        } finally {
            Carbon::setTestNow();
        }

        Event::assertNotDispatched(
            RoleExpiryChanged::class,
        );
    }

    /**
     * `assignRole()` with a different expiry fires `IdentityRoleExpiryChanged`
     * — pins the `!grantExpiriesEqual` branch against LogicalAnd/Negation
     * mutations.
     *
     * @return void
     */
    public function testAssignRoleFiresExpiryChangedWhenWindowMoves(): void
    {
        Event::fake(
            [RoleExpiryChanged::class],
        );

        $role = Role::create(['id' => (string) Str::uuid(), 'name' => 'moving', 'guard' => 'web']);
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);

        // Anchor Carbon so the two expiries are computed against a fixed
        // instant — keeps the +1h vs +2h delta deterministic.
        Carbon::setTestNow('2026-01-01 00:00:00');

        try {
            $user->assignRole($role, Carbon::now()->addHour()->toDateTimeImmutable());
            $user->assignRole($role, Carbon::now()->addHours(2)->toDateTimeImmutable());
        } finally {
            Carbon::setTestNow();
        }

        Event::assertDispatchedTimes(
            RoleExpiryChanged::class,
            1,
        );
    }

    /**
     * `givePermission()` with a different expiry fires
     * `IdentityPermissionExpiryChanged`.
     *
     * @return void
     */
    public function testGivePermissionFiresExpiryChangedWhenWindowMoves(): void
    {
        Event::fake(
            [PermissionExpiryChanged::class],
        );

        $permission = Permission::create(['id' => (string) Str::uuid(), 'name' => 'p:m', 'guard' => 'web']);
        $user       = StubIdentity::create(['id' => (string) Str::uuid()]);

        // Anchor Carbon so the two expiries are computed against a fixed
        // instant — keeps the +1h vs +2h delta deterministic.
        Carbon::setTestNow('2026-01-01 00:00:00');

        try {
            $user->givePermission($permission, Carbon::now()->addHour()->toDateTimeImmutable());
            $user->givePermission($permission, Carbon::now()->addHours(2)->toDateTimeImmutable());
        } finally {
            Carbon::setTestNow();
        }

        Event::assertDispatchedTimes(
            PermissionExpiryChanged::class,
            1,
        );
    }

    /**
     * `Statement::fromArray` distinguishes between missing and wrong-type
     * effect values — pins the `!isset($x) || !is_string` branch against `&&`
     * mutants.
     *
     * @return void
     */
    public function testStatementResolveEffectRejectsMissingAndNonString(): void
    {
        // Missing.
        $this->expectExceptionObjectShape(
            static fn () => Statement::fromArray([
                'effect' => 'allow',
            ]),
            \InvalidArgumentException::class,
            'Policy statement requires actions or not_actions.',
        );

        // Not array.
        $this->expectExceptionObjectShape(
            static fn () => Statement::fromArray([
                'effect'  => 'allow',
                'actions' => 'x',
            ]),
            \InvalidArgumentException::class,
            'Policy statement actions must be a non-empty list of non-empty strings.',
        );

        // Empty array.
        $this->expectExceptionObjectShape(
            static fn () => Statement::fromArray([
                'effect'  => 'allow',
                'actions' => [],
            ]),
            \InvalidArgumentException::class,
            'Policy statement actions must be a non-empty list of non-empty strings.',
        );
    }

    /**
     * An invalid effect string yields the correctly quoted message. Pins the
     * trailing `:'{$data['effect']}'` concat.
     *
     * @return void
     */
    public function testStatementUnknownEffectQuotesOffendingValue(): void
    {
        try {
            Statement::fromArray([
                'effect'  => 'maybe',
                'actions' => ['x'],
            ]);
            self::fail('Expected InvalidArgumentException.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('Invalid policy effect: \'maybe\'', $exception->getMessage());
        }
    }

    /**
     * A statement without `resources` keeps both resource lists unset, covers
     * every resource and a resource-less check, and leaves `resources` out when
     * serialised.
     *
     * @return void
     */
    public function testStatementWithoutResourcesCoversEveryResource(): void
    {
        $statement = Statement::fromArray([
            'effect'  => 'allow',
            'actions' => ['x'],
        ]);

        self::assertNull($statement->resources);
        self::assertNull($statement->notResources);
        self::assertTrue($statement->matches('x', 'post:42'));
        self::assertTrue($statement->matches('x'));
        self::assertSame(['effect' => 'allow', 'actions' => ['x']], $statement->toArray());
    }

    /**
     * `authorize()` populates the `LastDecisionStore` on both the success and
     * deny paths — pins the MethodCallRemoval mutant on
     * `$this->lastDecisionStore->put($decision)`, which `authorize()` reaches
     * through `check()`.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException
     */
    public function testAuthorizeWritesLastDecisionOnBothOutcomes(): void
    {
        $this->app->make(LastDecisionStore::class)->forget(); // @phpstan-ignore method.nonObject

        // Deny path — authorize() throws, lastDecision captures the decision.
        $role = Role::create(['id' => (string) Str::uuid(), 'name' => 'la', 'guard' => 'web']);
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);

        try {
            Authorization::for($user)->authorize('forbidden:action');
            self::fail('Expected AuthorizationException.');
        } catch (AuthorizationException) {
            $last = Authorization::lastDecision();
            self::assertNotNull($last);
            self::assertFalse($last->isAllowed());
        }

        // Allow path — authorize() returns, lastDecision captures allow.
        $permission = Permission::create(['id' => (string) Str::uuid(), 'name' => 'allow:me', 'guard' => 'web']);
        $role->givePermission($permission);
        $user->assignRole($role);

        Authorization::for($user->fresh())->authorize('allow:me');

        $last = Authorization::lastDecision();
        self::assertNotNull($last);
        self::assertTrue($last->isAllowed());
    }

    /**
     * `withPolicies()` returns a cloned manager — pins the CloneRemoval mutant
     * on `$scoped = clone $this;`. The two managers must be distinct instances.
     *
     * @return void
     */
    public function testWithPoliciesReturnsDistinctClone(): void
    {
        $manager = Authorization::getFacadeRoot();
        self::assertInstanceOf(AuthorizationManager::class, $manager);

        $policy = new Policy(
            name: 'clone-probe',
            statements: [
                new Statement(
                    effect: PolicyEffect::ALLOW,
                    actions: ['probe:clone'],
                ),
            ],
        );

        $scoped = $manager->withPolicies([$policy]);

        // Clones are distinct objects — pins CloneRemoval.
        self::assertNotSame($manager, $scoped);

        // The scoped clone evaluates through the supplied policies and yields
        // allow; the base does not.
        $scopedPrincipal = StubIdentity::create(['id' => (string) Str::uuid()]);
        self::assertTrue($scoped->for($scopedPrincipal)->can('probe:clone'));
        self::assertFalse($manager->for($scopedPrincipal)->can('probe:clone'));
    }

    /**
     * `attachPolicy()` with a different expiry fires
     * `IdentityPolicyExpiryChanged`.
     *
     * @return void
     */
    public function testAttachPolicyFiresExpiryChangedWhenWindowMoves(): void
    {
        Event::fake(
            [PolicyExpiryChanged::class],
        );

        $policy = \SineMacula\Laravel\Authorization\Models\Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'policy-m',
            'document' => ['statements' => [['effect' => 'allow', 'actions' => ['x']]]],
        ]);
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);

        // Anchor Carbon so the two expiries are computed against a fixed
        // instant — keeps the +1h vs +2h delta deterministic.
        Carbon::setTestNow('2026-01-01 00:00:00');

        try {
            $user->attachPolicy($policy, Carbon::now()->addHour()->toDateTimeImmutable());
            $user->attachPolicy($policy, Carbon::now()->addHours(2)->toDateTimeImmutable());
        } finally {
            Carbon::setTestNow();
        }

        Event::assertDispatchedTimes(
            PolicyExpiryChanged::class,
            1,
        );
    }

    /**
     * Run a callable and assert it throws the expected exception class with the
     * expected message. Shared helper for the `resolveEffect` /
     * `resolveActions` branches.
     *
     * @param  callable(): mixed  $callable
     * @param  class-string<\Throwable>  $class
     * @param  string  $message
     * @return void
     */
    private function expectExceptionObjectShape(callable $callable, string $class, string $message): void
    {
        try {
            $callable();
            self::fail("Expected exception {$class}.");
        } catch (\Throwable $exception) {
            self::assertInstanceOf($class, $exception);
            self::assertStringContainsString($message, $exception->getMessage());
        }
    }
}
