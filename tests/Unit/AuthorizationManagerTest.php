<?php

declare(strict_types = 1);

namespace Tests\Unit;

use Illuminate\Contracts\Events\Dispatcher;
use Mockery;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableIdentity;
use SineMacula\Laravel\Authorization\Contracts\PolicyStore;
use SineMacula\Laravel\Authorization\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\LastDecisionStore;
use SineMacula\Laravel\Authorization\Evaluation\Policy;
use SineMacula\Laravel\Authorization\Evaluation\PolicyEvaluator;
use SineMacula\Laravel\Authorization\Events\AuthorizationFailed;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Resolvers\DefaultPolicyResolver;
use SineMacula\Laravel\Authorization\Resolvers\NullPrincipalResolver;

/**
 * Unit tests for the authorization manager using stub principals and
 * a real evaluator — no Laravel boot required.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 * @SuppressWarnings("php:S1448")
 */
#[CoversClass(AuthorizationManager::class)]
final class AuthorizationManagerTest extends TestCase
{
    /**
     * Tear down Mockery instances after every test.
     *
     * @return void
     */
    protected function tearDown(): void
    {
        \Mockery::close();

        parent::tearDown();
    }

    /**
     * Anonymous resolver yields implicit deny on can().
     *
     * @return void
     */
    public function testAnonymousCanReturnsFalse(): void
    {
        $manager = new AuthorizationManager(
            evaluator: new PolicyEvaluator,
            principalResolver: new NullPrincipalResolver,
            policyResolver: new DefaultPolicyResolver,
            lastDecisionStore: new LastDecisionStore,
        );

        self::assertFalse($manager->can('posts:create'));
    }

    /**
     * Anonymous resolver causes authorize() to throw AuthorizationException.
     *
     * @return void
     */
    public function testAnonymousAuthorizeThrows(): void
    {
        $manager = new AuthorizationManager(
            evaluator: new PolicyEvaluator,
            principalResolver: new NullPrincipalResolver,
            policyResolver: new DefaultPolicyResolver,
            lastDecisionStore: new LastDecisionStore,
        );

        $this->expectException(AuthorizationException::class);

        $manager->authorize('posts:create');
    }

    /**
     * for() returns a scoped manager that uses the supplied principal.
     *
     * @return void
     */
    public function testForOverridesResolver(): void
    {
        $manager = new AuthorizationManager(
            evaluator: new PolicyEvaluator,
            principalResolver: new NullPrincipalResolver,
            policyResolver: new DefaultPolicyResolver,
            lastDecisionStore: new LastDecisionStore,
        );

        $principal = $this->stubAuthorizable(['posts:create']);
        $scoped    = $manager->for($principal);

        self::assertNotSame($manager, $scoped);
        self::assertTrue($scoped->can('posts:create'));
        self::assertFalse($manager->can('posts:create'));
    }

    /**
     * RBAC permission grants allow when no policies match.
     *
     * @return void
     */
    public function testRbacAllowedWhenPolicyDoesNotMatch(): void
    {
        $manager = new AuthorizationManager(
            evaluator: new PolicyEvaluator,
            principalResolver: new NullPrincipalResolver,
            policyResolver: new DefaultPolicyResolver,
            lastDecisionStore: new LastDecisionStore,
        );

        $principal = $this->stubAuthorizable(['posts:create'], [
            Policy::fromArray([
                'name'       => 'noise',
                'statements' => [['effect' => 'allow', 'actions' => ['users:read']]],
            ]),
        ]);

        $result = $manager->for($principal)->evaluate('posts:create');

        self::assertTrue($result->allowed);
        self::assertSame(DecisionReason::RbacAllow, $result->reason);
    }

    /**
     * Policy explicit allow takes precedence (and the RBAC fallback is skipped).
     *
     * @return void
     */
    public function testPolicyExplicitAllowReason(): void
    {
        $manager = new AuthorizationManager(
            evaluator: new PolicyEvaluator,
            principalResolver: new NullPrincipalResolver,
            policyResolver: new DefaultPolicyResolver,
            lastDecisionStore: new LastDecisionStore,
        );

        $principal = $this->stubAuthorizable([], [
            Policy::fromArray([
                'name'       => 'allow-create',
                'statements' => [['effect' => 'allow', 'actions' => ['posts:create']]],
            ]),
        ]);

        $result = $manager->for($principal)->evaluate('posts:create');

        self::assertTrue($result->allowed);
        self::assertSame(DecisionReason::ExplicitAllow, $result->reason);
    }

    /**
     * Policy explicit deny overrides RBAC allow.
     *
     * @return void
     */
    public function testExplicitDenyOverridesRbac(): void
    {
        $manager = new AuthorizationManager(
            evaluator: new PolicyEvaluator,
            principalResolver: new NullPrincipalResolver,
            policyResolver: new DefaultPolicyResolver,
            lastDecisionStore: new LastDecisionStore,
        );

        $principal = $this->stubAuthorizable(['posts:delete'], [
            Policy::fromArray([
                'name'       => 'deny',
                'statements' => [['effect' => 'deny', 'actions' => ['posts:delete']]],
            ]),
        ]);

        $result = $manager->for($principal)->evaluate('posts:delete');

        self::assertFalse($result->allowed);
        self::assertSame(DecisionReason::ExplicitDeny, $result->reason);
    }

    /**
     * withPolicies overrides the principal's policies and the policy store.
     *
     * @return void
     */
    /**
     * withPolicies returns a fresh scope and does not mutate the
     * originating manager (kills the "remove clone" mutant).
     *
     * @return void
     */
    public function testWithPoliciesReturnsCloneNotSelf(): void
    {
        $manager = new AuthorizationManager(
            evaluator: new PolicyEvaluator,
            principalResolver: new NullPrincipalResolver,
            policyResolver: new DefaultPolicyResolver,
            lastDecisionStore: new LastDecisionStore,
        );

        $principal = $this->stubAuthorizable(['rbac:do']);

        $override = Policy::fromArray([
            'name'       => 'override',
            'statements' => [['effect' => 'deny', 'actions' => ['rbac:do']]],
        ]);

        $scoped = $manager->for($principal)->withPolicies([$override]);

        self::assertNotSame($manager, $scoped);

        // The original manager (no override, no for()) still goes through the
        // anonymous resolver and returns false.
        self::assertFalse($manager->can('rbac:do'));

        // The scoped manager applies the override and denies.
        self::assertFalse($scoped->can('rbac:do'));

        // Without the override the same scoped principal would be allowed via
        // RBAC — proving the override is what made the deny.
        self::assertTrue($manager->for($principal)->can('rbac:do'));
    }

    /**
     * for() also returns a clone without mutating the original.
     *
     * @return void
     */
    public function testForReturnsCloneNotSelf(): void
    {
        $manager = new AuthorizationManager(
            evaluator: new PolicyEvaluator,
            principalResolver: new NullPrincipalResolver,
            policyResolver: new DefaultPolicyResolver,
            lastDecisionStore: new LastDecisionStore,
        );

        $principal = $this->stubAuthorizable(['x']);
        $scoped    = $manager->for($principal);

        self::assertNotSame($manager, $scoped);
        self::assertTrue($scoped->can('x'));
        self::assertFalse($manager->can('x'));
    }

    /**
     * @return void
     */
    public function testWithPoliciesOverridesEverything(): void
    {
        $store = \Mockery::mock(PolicyStore::class);
        $store->shouldNotReceive('policiesFor');

        $manager = new AuthorizationManager(
            evaluator: new PolicyEvaluator,
            principalResolver: new NullPrincipalResolver,
            policyResolver: new DefaultPolicyResolver(store: $store),
            lastDecisionStore: new LastDecisionStore,
        );

        $principal = $this->stubAuthorizable([], [
            Policy::fromArray([
                'name'       => 'principal',
                'statements' => [['effect' => 'deny', 'actions' => ['x']]],
            ]),
        ]);

        $override = Policy::fromArray([
            'name'       => 'override',
            'statements' => [['effect' => 'allow', 'actions' => ['x']]],
        ]);

        $result = $manager->for($principal)->withPolicies([$override])->evaluate('x');

        self::assertTrue($result->allowed);
    }

    /**
     * PolicyStore is consulted alongside the principal's own policies.
     *
     * @return void
     */
    public function testPolicyStoreContributesPolicies(): void
    {
        $principal = $this->stubAuthorizable();

        $store = \Mockery::mock(PolicyStore::class);
        $store->shouldReceive('policiesFor')
            ->once()
            ->with($principal)
            ->andReturn([
                Policy::fromArray([
                    'name'       => 'store',
                    'statements' => [['effect' => 'allow', 'actions' => ['from:store']]],
                ]),
            ]);

        $manager = new AuthorizationManager(
            evaluator: new PolicyEvaluator,
            principalResolver: new NullPrincipalResolver,
            policyResolver: new DefaultPolicyResolver(store: $store),
            lastDecisionStore: new LastDecisionStore,
        );

        self::assertTrue($manager->for($principal)->can('from:store'));
    }

    /**
     * DecisionEvaluated fires on every evaluation.
     *
     * @return void
     */
    public function testDecisionEventDispatched(): void
    {
        $events = \Mockery::mock(Dispatcher::class);
        $events->shouldReceive('dispatch')
            ->once()
            ->with(\Mockery::type(DecisionEvaluated::class));

        $manager = new AuthorizationManager(
            evaluator: new PolicyEvaluator,
            principalResolver: new NullPrincipalResolver,
            policyResolver: new DefaultPolicyResolver,
            lastDecisionStore: new LastDecisionStore,
            events: $events,
        );

        $manager->evaluate('x');

        // Mockery throws on unmet expectations during tearDown.
        self::assertTrue(true);
    }

    /**
     * authorize() dispatches both DecisionEvaluated and AuthorizationFailed before throwing.
     *
     * @return void
     */
    public function testAuthorizeFailsDispatchesBothEvents(): void
    {
        $events = \Mockery::mock(Dispatcher::class);
        $events->shouldReceive('dispatch')
            ->once()
            ->with(\Mockery::type(DecisionEvaluated::class));
        $events->shouldReceive('dispatch')
            ->once()
            ->with(\Mockery::type(AuthorizationFailed::class));

        $manager = new AuthorizationManager(
            evaluator: new PolicyEvaluator,
            principalResolver: new NullPrincipalResolver,
            policyResolver: new DefaultPolicyResolver,
            lastDecisionStore: new LastDecisionStore,
            events: $events,
        );

        $this->expectException(AuthorizationException::class);

        $manager->authorize('x');
    }

    /**
     * authorize() succeeds silently when allowed.
     *
     * @return void
     */
    public function testAuthorizeReturnsVoidWhenAllowed(): void
    {
        $manager = new AuthorizationManager(
            evaluator: new PolicyEvaluator,
            principalResolver: new NullPrincipalResolver,
            policyResolver: new DefaultPolicyResolver,
            lastDecisionStore: new LastDecisionStore,
        );

        $principal = $this->stubAuthorizable(['ok']);

        $manager->for($principal)->authorize('ok');

        $this->expectNotToPerformAssertions();
    }

    /**
     * Resolver-provided principal is consumed when no for() override is in play.
     *
     * @return void
     */
    public function testResolverSuppliesPrincipal(): void
    {
        $principal = $this->stubAuthorizable(['from:resolver']);

        $resolver = \Mockery::mock(PrincipalResolver::class);
        $resolver->shouldReceive('resolve')->andReturn($principal);

        $manager = new AuthorizationManager(
            evaluator: new PolicyEvaluator,
            principalResolver: $resolver,
            policyResolver: new DefaultPolicyResolver,
            lastDecisionStore: new LastDecisionStore,
        );

        self::assertTrue($manager->can('from:resolver'));
    }

    /**
     * Non-Authorizable principal is treated as having no RBAC permissions.
     *
     * @return void
     */
    public function testNonAuthorizablePrincipalHasNoRbac(): void
    {
        $manager = new AuthorizationManager(
            evaluator: new PolicyEvaluator,
            principalResolver: new NullPrincipalResolver,
            policyResolver: new DefaultPolicyResolver,
            lastDecisionStore: new LastDecisionStore,
        );

        $plain = (object) ['id' => 1];

        self::assertFalse($manager->for($plain)->can('anything'));
    }

    /**
     * `evaluate()` writes the result to the last-decision store.
     * Pins the MethodCallRemoval mutant on line 145.
     *
     * @return void
     */
    public function testEvaluateWritesToLastDecisionStore(): void
    {
        $store   = new LastDecisionStore;
        $manager = new AuthorizationManager(
            evaluator: new PolicyEvaluator,
            principalResolver: new NullPrincipalResolver,
            policyResolver: new DefaultPolicyResolver,
            lastDecisionStore: $store,
        );

        self::assertNull($manager->lastDecision());

        $manager->evaluate('some:action');

        self::assertNotNull($manager->lastDecision());
        self::assertSame(DecisionReason::ImplicitDeny, $manager->lastDecision()->reason);
    }

    /**
     * `withPolicies()` wraps the input through `array_values()`.
     * Pins the UnwrapArrayValues mutant on line 267.
     *
     * @return void
     */
    public function testWithPoliciesReindexesArray(): void
    {
        $manager = new AuthorizationManager(
            evaluator: new PolicyEvaluator,
            principalResolver: new NullPrincipalResolver,
            policyResolver: new DefaultPolicyResolver,
            lastDecisionStore: new LastDecisionStore,
        );

        $policy = Policy::fromArray([
            'name'       => 'reindex',
            'statements' => [['effect' => 'allow', 'actions' => ['x']]],
        ]);

        // Provide a non-zero-indexed array.
        $scoped = $manager->withPolicies([5 => $policy]);

        $principal = $this->stubAuthorizable();
        $result    = $scoped->for($principal)->evaluate('x');

        self::assertTrue($result->allowed);
    }

    /**
     * `dispatch()` is a no-op when events is null. Pins the
     * NullSafeMethodCall mutant on line 349.
     *
     * @return void
     */
    public function testDispatchNoOpWithoutEvents(): void
    {
        $manager = new AuthorizationManager(
            evaluator: new PolicyEvaluator,
            principalResolver: new NullPrincipalResolver,
            policyResolver: new DefaultPolicyResolver,
            lastDecisionStore: new LastDecisionStore,
            events: null,
        );

        // Should not throw.
        $manager->evaluate('x');

        self::assertTrue(true, 'dispatch() must not throw when events is null.');
    }

    /**
     * `for()` produces a clone. The clone's principal override is
     * isolated. Pins the CloneRemoval mutant on line 249.
     *
     * @return void
     */
    public function testForCloneIsolatesPrincipalOverride(): void
    {
        $manager = new AuthorizationManager(
            evaluator: new PolicyEvaluator,
            principalResolver: new NullPrincipalResolver,
            policyResolver: new DefaultPolicyResolver,
            lastDecisionStore: new LastDecisionStore,
        );

        $a = $this->stubAuthorizable(['a:do']);
        $b = $this->stubAuthorizable(['b:do']);

        $scopedA = $manager->for($a);
        $scopedB = $manager->for($b);

        // Each scope sees only its own principal.
        self::assertTrue($scopedA->can('a:do'));
        self::assertFalse($scopedA->can('b:do'));
        self::assertTrue($scopedB->can('b:do'));
        self::assertFalse($scopedB->can('a:do'));

        // Original remains anonymous.
        self::assertFalse($manager->can('a:do'));
    }

    /**
     * Build a stubbed authorizable principal returning the supplied
     * permissions and policies.
     *
     * @param  array<int, string>  $permissions
     * @param  array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>  $policies
     * @return \SineMacula\Laravel\Authorization\Contracts\AuthorizableIdentity
     */
    private function stubAuthorizable(array $permissions = [], array $policies = []): AuthorizableIdentity
    {
        $principal = \Mockery::mock(AuthorizableIdentity::class);

        $principal->shouldReceive('hasPermission')
            ->andReturnUsing(static fn (mixed $permission): bool => \in_array($permission, $permissions, true));

        $principal->shouldReceive('getPolicies')
            ->andReturn($policies);

        return $principal;
    }
}
