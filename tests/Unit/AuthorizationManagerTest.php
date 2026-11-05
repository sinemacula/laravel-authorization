<?php

declare(strict_types = 1);

namespace Tests\Unit;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Translation\Translator;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableIdentity;
use SineMacula\Laravel\Authorization\Contracts\PolicyStore;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\LastDecisionStore;
use SineMacula\Laravel\Authorization\Evaluation\Policy;
use SineMacula\Laravel\Authorization\Evaluation\PolicyEvaluator;
use SineMacula\Laravel\Authorization\Events\AuthorizationFailed;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Resolvers\DefaultPolicyResolver;
use SineMacula\Laravel\Authorization\Subject;
use Tests\Feature\Stubs\StubSubjectResolver;

/**
 * Unit tests for the authorization manager using stub principals and a real
 * evaluator — no Laravel boot required.
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
    #[\Override]
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
            subjectResolver: new StubSubjectResolver,
            policyResolver: new DefaultPolicyResolver,
            lastDecisionStore: new LastDecisionStore,
        );

        self::assertFalse($manager->can('posts:create'));
    }

    /**
     * Anonymous resolver causes authorize() to throw AuthorizationException.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public function testAnonymousAuthorizeThrows(): void
    {
        $manager = new AuthorizationManager(
            evaluator: new PolicyEvaluator,
            subjectResolver: new StubSubjectResolver,
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
            subjectResolver: new StubSubjectResolver,
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
            subjectResolver: new StubSubjectResolver,
            policyResolver: new DefaultPolicyResolver,
            lastDecisionStore: new LastDecisionStore,
        );

        $principal = $this->stubAuthorizable(['posts:create'], [
            Policy::fromArray([
                'name'       => 'noise',
                'statements' => [['effect' => 'allow', 'actions' => ['users:read']]],
            ]),
        ]);

        $decision = $manager->for($principal)->evaluate('posts:create');

        self::assertTrue($decision->allowed);
        self::assertSame(DecisionReason::RBAC_ALLOW, $decision->reason);
    }

    /**
     * Policy explicit allow takes precedence (and the RBAC fallback is
     * skipped).
     *
     * @return void
     */
    public function testPolicyExplicitAllowReason(): void
    {
        $manager = new AuthorizationManager(
            evaluator: new PolicyEvaluator,
            subjectResolver: new StubSubjectResolver,
            policyResolver: new DefaultPolicyResolver,
            lastDecisionStore: new LastDecisionStore,
        );

        $principal = $this->stubAuthorizable([], [
            Policy::fromArray([
                'name'       => 'allow-create',
                'statements' => [['effect' => 'allow', 'actions' => ['posts:create']]],
            ]),
        ]);

        $decision = $manager->for($principal)->evaluate('posts:create');

        self::assertTrue($decision->allowed);
        self::assertSame(DecisionReason::EXPLICIT_ALLOW, $decision->reason);
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
            subjectResolver: new StubSubjectResolver,
            policyResolver: new DefaultPolicyResolver,
            lastDecisionStore: new LastDecisionStore,
        );

        $principal = $this->stubAuthorizable(['posts:delete'], [
            Policy::fromArray([
                'name'       => 'deny',
                'statements' => [['effect' => 'deny', 'actions' => ['posts:delete']]],
            ]),
        ]);

        $decision = $manager->for($principal)->evaluate('posts:delete');

        self::assertFalse($decision->allowed);
        self::assertSame(DecisionReason::EXPLICIT_DENY, $decision->reason);
    }

    /**
     * withPolicies overrides the principal's policies and the policy store.
     *
     * @return void
     */
    /**
     * withPolicies returns a fresh scope and does not mutate the originating
     * manager (kills the "remove clone" mutant).
     *
     * @return void
     */
    public function testWithPoliciesReturnsCloneNotSelf(): void
    {
        $manager = new AuthorizationManager(
            evaluator: new PolicyEvaluator,
            subjectResolver: new StubSubjectResolver,
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
            subjectResolver: new StubSubjectResolver,
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
            subjectResolver: new StubSubjectResolver,
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

        $decision = $manager->for($principal)->withPolicies([$override])->evaluate('x');

        self::assertTrue($decision->allowed);
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
            subjectResolver: new StubSubjectResolver,
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
            subjectResolver: new StubSubjectResolver,
            policyResolver: new DefaultPolicyResolver,
            lastDecisionStore: new LastDecisionStore,
            events: $events,
        );

        $manager->evaluate('x');

        // Mockery throws on unmet expectations during tearDown.
        self::assertTrue(true);
    }

    /**
     * authorize() dispatches both DecisionEvaluated and AuthorizationFailed
     * before throwing.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
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
            subjectResolver: new StubSubjectResolver,
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
            subjectResolver: new StubSubjectResolver,
            policyResolver: new DefaultPolicyResolver,
            lastDecisionStore: new LastDecisionStore,
        );

        $principal = $this->stubAuthorizable(['ok']);

        // authorize() returns void on a granted decision and throws on a denial
        // — confirm the allowed path does not raise.
        $threw = false;

        try {
            $manager->for($principal)->authorize('ok');
        } catch (\Throwable $exception) {
            $threw = true;
        }

        self::assertFalse($threw, 'authorize() must not throw when the decision allows.');
    }

    /**
     * The resolver's subject is decided about when no for() scope is in play.
     *
     * @return void
     */
    public function testResolverSuppliesPrincipal(): void
    {
        $principal = $this->stubAuthorizable(['from:resolver']);

        $resolver = \Mockery::mock(SubjectResolver::class);
        $resolver->shouldReceive('resolve')->andReturn(new Subject($principal));

        $manager = new AuthorizationManager(
            evaluator: new PolicyEvaluator,
            subjectResolver: $resolver,
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
            subjectResolver: new StubSubjectResolver,
            policyResolver: new DefaultPolicyResolver,
            lastDecisionStore: new LastDecisionStore,
        );

        $plain = (object) ['id' => 1];

        self::assertFalse($manager->for($plain)->can('anything'));
    }

    /**
     * `evaluate()` writes the result to the last-decision store. Pins the
     * MethodCallRemoval mutant on line 145.
     *
     * @return void
     */
    public function testEvaluateWritesToLastDecisionStore(): void
    {
        $store   = new LastDecisionStore;
        $manager = new AuthorizationManager(
            evaluator: new PolicyEvaluator,
            subjectResolver: new StubSubjectResolver,
            policyResolver: new DefaultPolicyResolver,
            lastDecisionStore: $store,
        );

        self::assertNull($manager->lastDecision());

        $manager->evaluate('some:action');

        self::assertNotNull($manager->lastDecision());
        self::assertSame(DecisionReason::IMPLICIT_DENY, $manager->lastDecision()->reason);
    }

    /**
     * `withPolicies()` wraps the input through `array_values()`. Pins the
     * UnwrapArrayValues mutant on line 267.
     *
     * @return void
     */
    public function testWithPoliciesReindexesArray(): void
    {
        $manager = new AuthorizationManager(
            evaluator: new PolicyEvaluator,
            subjectResolver: new StubSubjectResolver,
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
        $decision  = $scoped->for($principal)->evaluate('x');

        self::assertTrue($decision->allowed);
    }

    /**
     * `dispatch()` is a no-op when events is null. Pins the NullSafeMethodCall
     * mutant on line 349.
     *
     * @return void
     */
    public function testDispatchNoOpWithoutEvents(): void
    {
        $manager = new AuthorizationManager(
            evaluator: new PolicyEvaluator,
            subjectResolver: new StubSubjectResolver,
            policyResolver: new DefaultPolicyResolver,
            lastDecisionStore: new LastDecisionStore,
            events: null,
        );

        // Should not throw.
        $manager->evaluate('x');

        self::assertTrue(true, 'dispatch() must not throw when events is null.');
    }

    /**
     * `for()` produces a clone. The clone's principal override is isolated.
     * Pins the CloneRemoval mutant on line 249.
     *
     * @return void
     */
    public function testForCloneIsolatesPrincipalOverride(): void
    {
        $manager = new AuthorizationManager(
            evaluator: new PolicyEvaluator,
            subjectResolver: new StubSubjectResolver,
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
     * A denial raised by `authorize()` carries the decision's reason code and
     * the translated `denied` line, and its message names neither the action
     * nor the resource.
     *
     * @return void
     */
    public function testAuthorizeDenialCarriesReasonAndTranslatedMessage(): void
    {
        $translator = \Mockery::mock(Translator::class);
        $translator->shouldReceive('get')
            ->once()
            ->with('authorization::authorization.denied')
            ->andReturn('Action non autorisée.');

        $deny = Policy::fromArray([
            'name'       => 'deny',
            'statements' => [['effect' => 'deny', 'actions' => ['posts:delete'], 'resources' => ['arn:posts:*']]],
        ]);

        $exception = $this->denialOf(
            $this->manager($translator)->for($this->stubAuthorizable())->withPolicies([$deny]),
            'posts:delete',
            'arn:posts:1',
        );

        self::assertSame(DecisionReason::EXPLICIT_DENY, $exception->getReason());
        self::assertSame('Action non autorisée.', $exception->getMessage());
    }

    /**
     * An anonymous denial carries the implicit-deny reason code.
     *
     * @return void
     */
    public function testAnonymousDenialCarriesImplicitDenyReason(): void
    {
        $exception = $this->denialOf($this->manager(), 'posts:create');

        self::assertSame(DecisionReason::IMPLICIT_DENY, $exception->getReason());
    }

    /**
     * Without a translator, the denial keeps Laravel's English message.
     *
     * @return void
     */
    public function testAuthorizeDenialWithoutTranslatorKeepsEnglishMessage(): void
    {
        $exception = $this->denialOf($this->manager(), 'posts:create', 'arn:posts:1');

        self::assertSame('This action is unauthorized.', $exception->getMessage());
    }

    /**
     * A translator without the package's line answers with the key itself;
     * the denial keeps the English message rather than showing the key.
     *
     * @return void
     */
    public function testAuthorizeDenialIgnoresAnUntranslatedKey(): void
    {
        $translator = \Mockery::mock(Translator::class);
        $translator->shouldReceive('get')->andReturn('authorization::authorization.denied');

        $exception = $this->denialOf($this->manager($translator), 'posts:create');

        self::assertSame('This action is unauthorized.', $exception->getMessage());
    }

    /**
     * A translator that answers with something other than a line leaves the
     * denial with the English message.
     *
     * @return void
     */
    public function testAuthorizeDenialIgnoresANonStringTranslation(): void
    {
        $translator = \Mockery::mock(Translator::class);
        $translator->shouldReceive('get')->andReturn(['denied' => 'Denied.']);

        $exception = $this->denialOf($this->manager($translator), 'posts:create');

        self::assertSame('This action is unauthorized.', $exception->getMessage());
    }

    /**
     * The current subject is the resolver's, and null when the resolver has
     * none.
     *
     * @return void
     */
    public function testCurrentSubjectIsTheResolversSubject(): void
    {
        $user   = new \stdClass;
        $tenant = new \stdClass;

        self::assertNull($this->managerResolving(new StubSubjectResolver)->currentSubject());

        $subject = $this->managerResolving(new StubSubjectResolver($user, $tenant, 'admin', 'web'))->currentSubject();

        self::assertNotNull($subject);
        self::assertSame($user, $subject->subject);
        self::assertSame($user, $subject->identity);
        self::assertSame($tenant, $subject->tenant);
        self::assertSame('admin', $subject->application);
        self::assertSame('web', $subject->guard);
    }

    /**
     * `for()` decides about the model named, in the request's tenant,
     * application and guard, and leaves the manager it was called on deciding
     * about the request's own subject.
     *
     * @return void
     */
    public function testForKeepsTheRequestsTenantApplicationAndGuard(): void
    {
        $user    = $this->stubAuthorizable();
        $other   = $this->stubAuthorizable(['posts:create']);
        $tenant  = new \stdClass;
        $manager = $this->managerResolving(new StubSubjectResolver($user, $tenant, 'admin', 'web'));

        $scoped  = $manager->for($other);
        $subject = $scoped->currentSubject();

        self::assertNotNull($subject);
        self::assertSame($other, $subject->subject);
        self::assertSame($other, $subject->identity);
        self::assertSame($tenant, $subject->tenant);
        self::assertSame('admin', $subject->application);
        self::assertSame('web', $subject->guard);
        self::assertTrue($scoped->can('posts:create'));
        self::assertFalse($manager->can('posts:create'));
        self::assertSame($user, $manager->currentSubject()?->subject);
    }

    /**
     * `for()` with no request subject decides about the model named, as its own
     * identity, in no tenant and on no application.
     *
     * @return void
     */
    public function testForWithoutARequestSubjectHasNoTenantOrApplication(): void
    {
        $other   = new \stdClass;
        $subject = $this->managerResolving(new StubSubjectResolver)->for($other)->currentSubject();

        self::assertNotNull($subject);
        self::assertSame($other, $subject->subject);
        self::assertSame($other, $subject->identity);
        self::assertNull($subject->tenant);
        self::assertNull($subject->application);
        self::assertNull($subject->guard);
    }

    /**
     * Naming the request's own subject keeps its identity, a second `for()`
     * keeps the tenant the first one carried, and neither translates through
     * `forUser()`.
     *
     * @return void
     */
    public function testForChainsKeepTheTenantAndTheRequestsIdentity(): void
    {
        $user     = new \stdClass;
        $identity = new \stdClass;
        $tenant   = new \stdClass;
        $request  = new Subject($user, $identity, $tenant, 'admin', 'web');

        $resolver = \Mockery::mock(SubjectResolver::class);
        $resolver->shouldReceive('resolve')->twice()->andReturn($request);
        $resolver->shouldNotReceive('forUser');

        $manager = $this->managerResolving($resolver);

        self::assertSame($request, $manager->for($user)->currentSubject());
        self::assertSame($tenant, $manager->for($user)->for(new \stdClass)->currentSubject()?->tenant);
    }

    /**
     * `forUser()` decides about the subject the resolver translates the user
     * into, never about the user itself.
     *
     * @return void
     */
    public function testForUserDecidesAboutTheResolversTranslation(): void
    {
        $user      = new \stdClass;
        $principal = $this->stubAuthorizable(['posts:create']);
        $resolved  = new Subject($principal, $user);

        $resolver = \Mockery::mock(SubjectResolver::class);
        $resolver->shouldReceive('forUser')->once()->with($user)->andReturn($resolved);
        $resolver->shouldReceive('resolve')->andReturnNull();

        $manager = $this->managerResolving($resolver);
        $scoped  = $manager->forUser($user);

        self::assertNotSame($manager, $scoped);
        self::assertSame($resolved, $scoped->currentSubject());
        self::assertTrue($scoped->can('posts:create'));
        self::assertNull($manager->currentSubject());
    }

    /**
     * The decision events carry the model the subject is about.
     *
     * @return void
     */
    public function testDecisionEventsCarryTheSubjectsModel(): void
    {
        $user   = $this->stubAuthorizable();
        $events = \Mockery::mock(Dispatcher::class);
        $events->shouldReceive('dispatch')->with(\Mockery::on(static fn (object $event): bool => $event instanceof DecisionEvaluated && $event->principal === $user))->twice();
        $events->shouldReceive('dispatch')->with(\Mockery::on(static fn (object $event): bool => $event instanceof AuthorizationFailed && $event->principal === $user))->once();

        $manager = new AuthorizationManager(
            evaluator: new PolicyEvaluator,
            subjectResolver: new StubSubjectResolver($user),
            policyResolver: new DefaultPolicyResolver,
            lastDecisionStore: new LastDecisionStore,
            events: $events,
        );

        $manager->evaluate('posts:create');
        $exception = $this->denialOf($manager, 'posts:create');

        self::assertSame(DecisionReason::IMPLICIT_DENY, $exception->getReason());
    }

    /**
     * Build a manager resolving its subject through the supplied resolver.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\SubjectResolver  $resolver
     * @return \SineMacula\Laravel\Authorization\AuthorizationManager
     */
    private function managerResolving(SubjectResolver $resolver): AuthorizationManager
    {
        return new AuthorizationManager(
            evaluator: new PolicyEvaluator,
            subjectResolver: $resolver,
            policyResolver: new DefaultPolicyResolver,
            lastDecisionStore: new LastDecisionStore,
        );
    }

    /**
     * Build a manager with an anonymous resolver and the supplied translator.
     *
     * @param  \Illuminate\Contracts\Translation\Translator|null  $translator
     * @return \SineMacula\Laravel\Authorization\AuthorizationManager
     */
    private function manager(?Translator $translator = null): AuthorizationManager
    {
        return new AuthorizationManager(
            evaluator: new PolicyEvaluator,
            subjectResolver: new StubSubjectResolver,
            policyResolver: new DefaultPolicyResolver,
            lastDecisionStore: new LastDecisionStore,
            translator: $translator,
        );
    }

    /**
     * Run `authorize()` and return the denial it raises.
     *
     * @param  \SineMacula\Laravel\Authorization\AuthorizationManager  $manager
     * @param  string  $action
     * @param  string|null  $resource
     * @return \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    private function denialOf(AuthorizationManager $manager, string $action, ?string $resource = null): AuthorizationException
    {
        try {
            $manager->authorize($action, $resource);
        } catch (AuthorizationException $exception) {
            return $exception;
        }

        self::fail('Expected AuthorizationException.');
    }

    /**
     * Build a stubbed authorizable principal returning the supplied permissions
     * and policies.
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
