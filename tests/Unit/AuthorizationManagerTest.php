<?php

declare(strict_types = 1);

namespace Tests\Unit;

use Illuminate\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Translation\Translator;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Context\CheckContextFactory;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationContext;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableIdentity;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableMachine;
use SineMacula\Laravel\Authorization\Contracts\EnvironmentContext;
use SineMacula\Laravel\Authorization\Contracts\PolicyResolver;
use SineMacula\Laravel\Authorization\Contracts\PolicyStore;
use SineMacula\Laravel\Authorization\Contracts\RequestContext;
use SineMacula\Laravel\Authorization\Contracts\ResourceTenantResolver;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\Enums\TraceOutcome;
use SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException;
use SineMacula\Laravel\Authorization\Evaluation\LastDecisionStore;
use SineMacula\Laravel\Authorization\Evaluation\Policy;
use SineMacula\Laravel\Authorization\Evaluation\PolicyEvaluator;
use SineMacula\Laravel\Authorization\Evaluation\StatementReference;
use SineMacula\Laravel\Authorization\Evaluation\TraceEntry;
use SineMacula\Laravel\Authorization\Events\AuthorizationFailed;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidCheckArgumentException;
use SineMacula\Laravel\Authorization\Resolvers\DefaultPolicyResolver;
use SineMacula\Laravel\Authorization\Resolvers\NoResourceTenant;
use SineMacula\Laravel\Authorization\Resolvers\SessionCapResolver;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubSessionPolicySource;
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
     * Tear down Mockery instances and forget any container a test set after
     * every test.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        \Mockery::close();
        Container::setInstance(null);

        parent::tearDown();
    }

    /**
     * Anonymous resolver yields a denial on can().
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
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException
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
     * A permission the subject holds allows when no statement decides the
     * check: the decision is an allow at the allow stage, decided by no
     * statement, with the held permission appended to the evaluator's trace.
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

        $decision = $manager->for($principal)->check('posts:create');

        self::assertTrue($decision->isAllowed());
        self::assertNull($decision->reason);
        self::assertSame(DecisionStage::ALLOW, $decision->stage);
        self::assertSame([], $decision->statements);
        self::assertEquals([
            ...self::uncapped(),
            new TraceEntry(DecisionStage::ALLOW, TraceOutcome::NOT_APPLICABLE, new StatementReference('noise', 0)),
            new TraceEntry(DecisionStage::ALLOW, TraceOutcome::HELD, null, [], null, 'posts:create'),
        ], $decision->trace);
    }

    /**
     * A permission the subject does not hold keeps the evaluator's denial, its
     * reason and its stage, and appends the step that found it not held.
     *
     * @return void
     */
    public function testPermissionNotHeldAppendsTheStepAndKeepsTheDenial(): void
    {
        $principal = $this->stubAuthorizable(['users:read'], [
            Policy::fromArray([
                'name'       => 'noise',
                'statements' => [['effect' => 'allow', 'actions' => ['users:read']]],
            ]),
        ]);

        $decision = $this->manager()->for($principal)->check('posts:create');

        self::assertFalse($decision->isAllowed());
        self::assertSame(DecisionReason::NO_MATCH, $decision->reason);
        self::assertSame(DecisionStage::IMPLICIT, $decision->stage);
        self::assertSame([], $decision->statements);
        self::assertEquals([
            ...self::uncapped(),
            new TraceEntry(DecisionStage::ALLOW, TraceOutcome::NOT_APPLICABLE, new StatementReference('noise', 0)),
            new TraceEntry(DecisionStage::ALLOW, TraceOutcome::NOT_HELD),
        ], $decision->trace);
    }

    /**
     * An allow statement whose conditions do not hold leaves the check to the
     * permission step: a permission not held keeps the `condition_failed`
     * denial, and a permission held turns it into an allow, the statement's
     * failed condition kept in the trace either way.
     *
     * @return void
     */
    public function testPermissionStepFollowsAnAllowWhoseConditionsFail(): void
    {
        $policy = Policy::fromArray([
            'name'       => 'tenant-only',
            'statements' => [['effect' => 'allow', 'actions' => ['posts:create'], 'conditions' => ['eq' => ['input.tenant' => 'org-1']]]],
        ]);

        $failed = new TraceEntry(DecisionStage::ALLOW, TraceOutcome::CONDITION_FAILED, new StatementReference('tenant-only', 0), ['input.tenant' => false]);

        $denied  = $this->manager()->for($this->stubAuthorizable([], [$policy]))->check('posts:create', null, ['tenant' => 'org-2']);
        $allowed = $this->manager()->for($this->stubAuthorizable(['posts:create'], [$policy]))->check('posts:create', null, ['tenant' => 'org-2']);

        self::assertSame(DecisionReason::CONDITION_FAILED, $denied->reason);
        self::assertSame(DecisionStage::IMPLICIT, $denied->stage);
        self::assertEquals([...self::uncapped(), $failed, new TraceEntry(DecisionStage::ALLOW, TraceOutcome::NOT_HELD)], $denied->trace);

        self::assertTrue($allowed->isAllowed());
        self::assertSame(DecisionStage::ALLOW, $allowed->stage);
        self::assertSame([], $allowed->statements);
        self::assertEquals([...self::uncapped(), $failed, new TraceEntry(DecisionStage::ALLOW, TraceOutcome::HELD, null, [], null, 'posts:create')], $allowed->trace);
    }

    /**
     * Without a check context factory, what the caller passes is read under
     * `input` alone: `['request' => ['ip' => …]]` supplies `input.request.ip`
     * and never `request.ip`, and a top-level key named `request.ip` is never
     * the path `request.ip`.
     *
     * @return void
     */
    public function testCallerValuesAreReadUnderInputAlone(): void
    {
        $principal = $this->stubAuthorizable([], [Policy::fromArray([
            'name'       => 'caller-values',
            'statements' => [
                ['effect' => 'allow', 'actions' => ['posts:create'], 'conditions' => ['eq' => ['input.request.ip' => '10.0.0.1']]],
                ['effect' => 'allow', 'actions' => ['posts:update'], 'conditions' => ['eq' => ['request.ip' => '10.0.0.1']]],
            ],
        ])]);

        $manager = $this->manager()->for($principal);

        self::assertTrue($manager->can('posts:create', null, ['request' => ['ip' => '10.0.0.1']]));
        self::assertFalse($manager->can('posts:create', null, ['input.request.ip' => '10.0.0.1']));
        self::assertFalse($manager->can('posts:update', null, ['request' => ['ip' => '10.0.0.1']]));
        self::assertFalse($manager->can('posts:update', null, ['request.ip' => '10.0.0.1']));
        self::assertSame(TraceOutcome::UNDECIDABLE, $manager->check('posts:update', null, ['request' => ['ip' => '10.0.0.1']])->trace[4]->outcome);
    }

    /**
     * Without a check context factory, the subject and the resource still
     * supply their built-in keys, so a statement on the resource's type and id
     * and on the subject's type decides by them.
     *
     * @return void
     */
    public function testTheBuiltInKeysAreSuppliedWithoutAFactory(): void
    {
        $principal = $this->stubAuthorizable([], [Policy::fromArray([
            'name'       => 'built-ins',
            'statements' => [[
                'effect'     => 'allow',
                'actions'    => ['posts:update'],
                'resources'  => ['*'],
                'conditions' => ['eq' => ['resource.type' => 'post', 'resource.id' => '42'], 'null' => ['subject.type' => false]],
            ]],
        ])]);

        $manager = $this->manager()->for($principal);

        self::assertTrue($manager->can('posts:update', ResourceReference::record('post', '42')));
        self::assertFalse($manager->can('posts:update', ResourceReference::record('post', '43')));
        self::assertFalse($manager->can('posts:update', ResourceReference::record('page', '42')));
        self::assertFalse($manager->can('posts:update', ResourceReference::type('post')));
    }

    /**
     * With a check context factory, each check's context holds the sources'
     * namespaces beside the caller's `input`, so a caller can never stand in
     * for the request, and a source is read once per check that reads it.
     *
     * @return void
     */
    public function testTheCheckContextComesFromTheFactorysSources(): void
    {
        $request = new class implements RequestContext {
            /** @var int How many times the request's values were read. */
            public int $reads = 0;

            /**
             * Return the request's values.
             *
             * @return array<string, mixed>
             */
            #[\Override]
            public function values(): array
            {
                $this->reads++;

                return ['ip' => '10.0.0.9', 'method' => 'GET'];
            }
        };

        $manager = new AuthorizationManager(
            evaluator: new PolicyEvaluator,
            subjectResolver: new StubSubjectResolver,
            policyResolver: new DefaultPolicyResolver,
            lastDecisionStore: new LastDecisionStore,
            contexts: new CheckContextFactory(self::authentication(), $request, self::environment()),
        );

        $principal = $this->stubAuthorizable([], [Policy::fromArray([
            'name'       => 'request-values',
            'statements' => [
                ['effect' => 'allow', 'actions' => ['posts:create'], 'conditions' => ['eq' => ['request.ip' => '10.0.0.9', 'request.method' => 'GET', 'input.post' => '1']]],
                ['effect' => 'allow', 'actions' => ['posts:update'], 'conditions' => ['eq' => ['request.ip' => '10.0.0.1']]],
                ['effect' => 'allow', 'actions' => ['posts:delete']],
            ],
        ])]);

        $scoped = $manager->for($principal);

        self::assertTrue($scoped->can('posts:create', null, ['post' => '1']));
        self::assertFalse($scoped->can('posts:create', null, ['post' => '2']));
        self::assertFalse($scoped->can('posts:update', null, ['request' => ['ip' => '10.0.0.1']]));
        self::assertSame(3, $request->reads);

        self::assertTrue($scoped->can('posts:delete'));
        self::assertSame(3, $request->reads);
    }

    /**
     * A policy allow decides the check at the allow stage, by its statement,
     * and the permission step is skipped: the trace holds the statement alone.
     *
     * @return void
     */
    public function testPolicyAllowDecidesAtTheAllowStage(): void
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

        $decision = $manager->for($principal)->check('posts:create');

        self::assertTrue($decision->isAllowed());
        self::assertNull($decision->reason);
        self::assertSame(DecisionStage::ALLOW, $decision->stage);
        self::assertEquals([new StatementReference('allow-create', 0)], $decision->statements);
        self::assertEquals([
            ...self::uncapped(),
            new TraceEntry(DecisionStage::ALLOW, TraceOutcome::MATCHED, new StatementReference('allow-create', 0)),
        ], $decision->trace);
    }

    /**
     * A policy explicit deny overrides a permission the subject holds: the
     * check is denied at the deny stage by the deny statement, and the
     * permission is never consulted.
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

        $decision = $manager->for($principal)->check('posts:delete');

        self::assertFalse($decision->isAllowed());
        self::assertSame(DecisionReason::EXPLICIT_DENY, $decision->reason);
        self::assertSame(DecisionStage::DENY, $decision->stage);
        self::assertEquals([new StatementReference('deny', 0)], $decision->statements);
        self::assertEquals([
            new TraceEntry(DecisionStage::DENY, TraceOutcome::MATCHED, new StatementReference('deny', 0)),
        ], $decision->trace);
    }

    /**
     * With no subject, the check is denied as `subject_unresolved` at the
     * subject stage, without reading any policy.
     *
     * @return void
     */
    public function testCheckDeniesWithoutASubjectAtTheSubjectStage(): void
    {
        $policies = \Mockery::mock(PolicyResolver::class);
        $policies->shouldNotReceive('policiesFor');

        $decision = $this->managerWithPolicies($policies, new StubSubjectResolver)->check('posts:create');

        self::assertFalse($decision->isAllowed());
        self::assertSame(DecisionReason::SUBJECT_UNRESOLVED, $decision->reason);
        self::assertSame(DecisionStage::SUBJECT, $decision->stage);
        self::assertSame([], $decision->statements);
        self::assertSame([], $decision->trace);
    }

    /**
     * An inactive subject is denied as `subject_inactive` at the subject stage,
     * whatever its permissions or policies would allow, and no policy is read.
     *
     * @return void
     */
    public function testCheckDeniesAnInactiveSubjectAtTheSubjectStage(): void
    {
        $principal = $this->stubAuthorizable(['posts:create'], [
            Policy::fromArray([
                'name'       => 'allow-create',
                'statements' => [['effect' => 'allow', 'actions' => ['posts:create']]],
            ]),
        ], active: false);

        $policies = \Mockery::mock(PolicyResolver::class);
        $policies->shouldNotReceive('policiesFor');

        $manager  = $this->managerWithPolicies($policies, new StubSubjectResolver($principal));
        $decision = $manager->check('posts:create');

        self::assertFalse($decision->isAllowed());
        self::assertSame(DecisionReason::SUBJECT_INACTIVE, $decision->reason);
        self::assertSame(DecisionStage::SUBJECT, $decision->stage);
        self::assertSame([], $decision->statements);
        self::assertSame([], $decision->trace);
        self::assertFalse($manager->can('posts:create'));
    }

    /**
     * A policy document that cannot be read denies the check as
     * `invalid_policy` at the deny stage, with an empty trace, even when the
     * subject holds the permission.
     *
     * @return void
     */
    public function testUnreadablePolicyDeniesAsInvalidPolicy(): void
    {
        $principal = $this->stubAuthorizable(['posts:create']);

        $policies = \Mockery::mock(PolicyResolver::class);
        $policies->shouldReceive('policiesFor')
            ->once()
            ->with($principal)
            ->andThrow(new InvalidPolicyDocumentException('broken', 'unreadable'));

        $decision = $this->managerWithPolicies($policies, new StubSubjectResolver($principal))->check('posts:create');

        self::assertFalse($decision->isAllowed());
        self::assertSame(DecisionReason::INVALID_POLICY, $decision->reason);
        self::assertSame(DecisionStage::DENY, $decision->stage);
        self::assertSame([], $decision->statements);
        self::assertSame([], $decision->trace);
    }

    /**
     * Resource arguments that cannot be identified: a number, a boolean, an
     * empty list, a list that is not a pair, a pair with a boolean key, an
     * object that cannot be named and an unsaved model.
     *
     * @return iterable<string, array{\Closure(): mixed}>
     */
    public static function unidentifiableResources(): iterable
    {
        yield 'a number' => [static fn (): int => 42];
        yield 'a boolean' => [static fn (): bool => true];
        yield 'an empty list' => [static fn (): array => []];
        yield 'a single-item list' => [static fn (): array => ['posts']];
        yield 'a pair with a boolean key' => [static fn (): array => ['posts', true]];
        yield 'an unnameable object' => [static fn (): object => new \stdClass];
        yield 'an unsaved model' => [static fn (): object => new StubIdentity];
    }

    /**
     * `check()` on a resource that cannot be identified denies as
     * `resource_unresolved` at the resource stage without consulting any policy
     * or permission, records the denial as the last decision and reports it
     * with `DecisionEvaluated`, without a resource.
     *
     * @param  \Closure(): mixed  $resource
     * @return void
     */
    #[DataProvider('unidentifiableResources')]
    public function testCheckDeniesAnUnidentifiableResourceAtTheResourceStage(\Closure $resource): void
    {
        $principal = $this->stubAuthorizable(['posts:update']);
        $reported  = [];

        $events = \Mockery::mock(Dispatcher::class);
        $events->shouldReceive('dispatch')
            ->once()
            ->andReturnUsing(static function (object $event) use (&$reported): void {
                $reported[] = $event;
            });

        $policies = \Mockery::mock(PolicyResolver::class);
        $policies->shouldNotReceive('policiesFor');

        $manager = new AuthorizationManager(
            evaluator: new PolicyEvaluator,
            subjectResolver: new StubSubjectResolver($principal),
            policyResolver: $policies,
            lastDecisionStore: new LastDecisionStore,
            events: $events,
        );

        $decision = $manager->check('posts:update', $resource(), ['tenant' => 'org-1']);

        self::assertFalse($decision->isAllowed());
        self::assertSame(DecisionReason::RESOURCE_UNRESOLVED, $decision->reason);
        self::assertSame(DecisionStage::RESOURCE, $decision->stage);
        self::assertSame([], $decision->statements);
        self::assertSame([], $decision->trace);
        self::assertSame($decision, $manager->lastDecision());
        self::assertCount(1, $reported);
        self::assertInstanceOf(DecisionEvaluated::class, $reported[0]);
        self::assertSame($principal, $reported[0]->principal);
        self::assertSame('posts:update', $reported[0]->action);
        self::assertNull($reported[0]->resource);
        self::assertSame(['tenant' => 'org-1'], $reported[0]->context);
        self::assertSame($decision, $reported[0]->decision);
    }

    /**
     * The subject stage still decides first: a check with no subject and a
     * resource that cannot be identified denies as `subject_unresolved` at the
     * subject stage, and an inactive subject as `subject_inactive`.
     *
     * @return void
     */
    public function testTheSubjectStageDecidesBeforeAnUnidentifiableResource(): void
    {
        $anonymous = $this->manager()->check('posts:update', 42);

        self::assertFalse($anonymous->isAllowed());
        self::assertSame(DecisionReason::SUBJECT_UNRESOLVED, $anonymous->reason);
        self::assertSame(DecisionStage::SUBJECT, $anonymous->stage);

        $inactive = $this->managerResolving(new StubSubjectResolver($this->stubAuthorizable(['posts:update'], active: false)))
            ->check('posts:update', 42);

        self::assertFalse($inactive->isAllowed());
        self::assertSame(DecisionReason::SUBJECT_INACTIVE, $inactive->reason);
        self::assertSame(DecisionStage::SUBJECT, $inactive->stage);
    }

    /**
     * `check()` names a pair, a model class, a nameable object, a plain string
     * and a resource reference to the evaluator by their identifiers — a pair
     * as `type:id`, a model class as `type:*` — so each is allowed by the one
     * statement written for that identifier, and `DecisionEvaluated` carries
     * the identifier string. A pair's tenant is asked of the bound resource
     * tenant resolver, so one that knows none is bound in a fresh container.
     *
     * @return void
     */
    public function testCheckNamesEachResourceByItsIdentifier(): void
    {
        Container::setInstance(new Container);
        Container::getInstance()->instance(ResourceTenantResolver::class, new NoResourceTenant);

        $principal = $this->stubAuthorizable([], [
            Policy::fromArray([
                'name'       => 'by-identifier',
                'statements' => [
                    ['effect' => 'allow', 'actions' => ['posts:read'], 'resources' => ['posts:7']],
                    ['effect' => 'allow', 'actions' => ['posts:read'], 'resources' => [StubIdentity::class . ':*']],
                    ['effect' => 'allow', 'actions' => ['posts:read'], 'resources' => ['report:q3']],
                    ['effect' => 'allow', 'actions' => ['posts:read'], 'resources' => ['arn:posts']],
                    ['effect' => 'allow', 'actions' => ['posts:read'], 'resources' => ['comments:9']],
                ],
            ]),
        ]);

        $reported = [];

        $events = \Mockery::mock(Dispatcher::class);
        $events->shouldReceive('dispatch')
            ->times(6)
            ->andReturnUsing(static function (DecisionEvaluated $event) use (&$reported): void {
                $reported[] = $event->resource;
            });

        $manager = new AuthorizationManager(
            evaluator: new PolicyEvaluator,
            subjectResolver: new StubSubjectResolver($principal),
            policyResolver: new DefaultPolicyResolver,
            lastDecisionStore: new LastDecisionStore,
            events: $events,
        );

        $nameable = new class implements \Stringable {
            /**
             * Return the resource's name.
             *
             * @return string
             */
            #[\Override]
            public function __toString(): string
            {
                return 'report:q3';
            }
        };

        $resources = [['posts', 7], StubIdentity::class, $nameable, 'arn:posts', ResourceReference::record('comments', '9')];

        foreach ($resources as $index => $resource) {
            $decision = $manager->check('posts:read', $resource);

            self::assertTrue($decision->isAllowed());
            self::assertSame(DecisionStage::ALLOW, $decision->stage);
            self::assertEquals([new StatementReference('by-identifier', $index)], $decision->statements);
        }

        $unmatched = $manager->check('posts:read', ['posts', 8]);

        self::assertFalse($unmatched->isAllowed());
        self::assertSame(DecisionReason::NO_MATCH, $unmatched->reason);
        self::assertSame(['posts:7', StubIdentity::class . ':*', 'report:q3', 'arn:posts', 'comments:9', 'posts:8'], $reported);
    }

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
     * withPolicies overrides the principal's policies and the policy store: the
     * override's allow decides the check, by its statement alone.
     *
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

        $decision = $manager->for($principal)->withPolicies([$override])->check('x');

        self::assertTrue($decision->isAllowed());
        self::assertEquals([new StatementReference('override', 0)], $decision->statements);
        self::assertCount(4, $decision->trace);
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
     * DecisionEvaluated fires once on every check, carrying the decision the
     * check returns.
     *
     * @return void
     */
    public function testDecisionEventDispatched(): void
    {
        $reported = [];

        $events = \Mockery::mock(Dispatcher::class);
        $events->shouldReceive('dispatch')
            ->once()
            ->with(\Mockery::type(DecisionEvaluated::class))
            ->andReturnUsing(static function (DecisionEvaluated $event) use (&$reported): void {
                $reported[] = $event;
            });

        $manager = new AuthorizationManager(
            evaluator: new PolicyEvaluator,
            subjectResolver: new StubSubjectResolver,
            policyResolver: new DefaultPolicyResolver,
            lastDecisionStore: new LastDecisionStore,
            events: $events,
        );

        $decision = $manager->check('x');

        self::assertCount(1, $reported);
        self::assertSame($decision, $reported[0]->decision);
        self::assertSame('x', $reported[0]->action);
    }

    /**
     * authorize() dispatches both DecisionEvaluated and AuthorizationFailed
     * before throwing.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException
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
     * authorize() reports the denial with AuthorizationFailed, carrying the
     * same decision the check recorded, and throws with the decision's reason.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException
     */
    public function testAuthorizeReportsTheDecisionAndThrowsWithItsReason(): void
    {
        $principal = $this->stubAuthorizable(['posts:delete'], [
            Policy::fromArray([
                'name'       => 'deny',
                'statements' => [['effect' => 'deny', 'actions' => ['posts:delete']]],
            ]),
        ]);

        $reported = [];

        $events = \Mockery::mock(Dispatcher::class);
        $events->shouldReceive('dispatch')
            ->twice()
            ->andReturnUsing(static function (object $event) use (&$reported): void {
                $reported[] = $event;
            });

        $manager = new AuthorizationManager(
            evaluator: new PolicyEvaluator,
            subjectResolver: new StubSubjectResolver($principal),
            policyResolver: new DefaultPolicyResolver,
            lastDecisionStore: new LastDecisionStore,
            events: $events,
        );

        $exception = $this->denialOf($manager, 'posts:delete', 'arn:posts:1');
        $decision  = $manager->lastDecision();

        self::assertInstanceOf(Decision::class, $decision);
        self::assertSame(DecisionReason::EXPLICIT_DENY, $decision->reason);
        self::assertSame($decision->reason, $exception->getReason());
        self::assertSame($decision, $exception->getDecision());
        self::assertCount(2, $reported);
        self::assertInstanceOf(DecisionEvaluated::class, $reported[0]);
        self::assertSame($decision, $reported[0]->decision);
        self::assertInstanceOf(AuthorizationFailed::class, $reported[1]);
        self::assertSame($decision, $reported[1]->decision);
        self::assertSame($principal, $reported[1]->principal);
        self::assertSame('posts:delete', $reported[1]->action);
        self::assertSame('arn:posts:1', $reported[1]->resource);
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
        self::assertTrue($manager->lastDecision()?->isAllowed());
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
     * `check()` records the decision it returns as the last decision, and
     * `can()` adapts the same recorded decision to whether it is allowed.
     *
     * @return void
     */
    public function testCheckRecordsTheDecisionAsTheLastDecision(): void
    {
        $store   = new LastDecisionStore;
        $manager = new AuthorizationManager(
            evaluator: new PolicyEvaluator,
            subjectResolver: new StubSubjectResolver,
            policyResolver: new DefaultPolicyResolver,
            lastDecisionStore: $store,
        );

        $before   = $manager->lastDecision();
        $decision = $manager->check('some:action');
        $recorded = $manager->lastDecision();

        self::assertNull($before);
        self::assertSame($decision, $recorded);
        self::assertSame($decision, $store->get());
        self::assertSame(DecisionReason::SUBJECT_UNRESOLVED, $decision->reason);

        $scoped = $manager->for($this->stubAuthorizable(['some:action']));

        self::assertTrue($scoped->can('some:action'));

        $last = $manager->lastDecision();

        self::assertNotNull($last);
        self::assertTrue($last->isAllowed());
        self::assertSame(DecisionStage::ALLOW, $last->stage);
    }

    /**
     * `explain()` returns the explanation of the decision `check()` makes.
     *
     * @return void
     */
    public function testExplainExplainsTheCheck(): void
    {
        $manager = $this->manager();

        self::assertSame('DENY (subject_unresolved: there is no subject) at the subject stage.', $manager->explain('posts:create'));
        self::assertSame($manager->check('posts:create')->explain(), $manager->explain('posts:create'));
    }

    /**
     * `withPolicies()` decides with policies given under any keys.
     *
     * @return void
     */
    public function testWithPoliciesAcceptsPoliciesUnderAnyKeys(): void
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
        $decision  = $scoped->for($principal)->check('x');

        self::assertTrue($decision->isAllowed());
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
        $manager->check('x');

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
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException
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
     * An anonymous denial carries the `subject_unresolved` reason code.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException
     */
    public function testAnonymousDenialCarriesSubjectUnresolvedReason(): void
    {
        $exception = $this->denialOf($this->manager(), 'posts:create');

        self::assertSame(DecisionReason::SUBJECT_UNRESOLVED, $exception->getReason());
    }

    /**
     * Without a translator, the denial keeps Laravel's English message.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException
     */
    public function testAuthorizeDenialWithoutTranslatorKeepsEnglishMessage(): void
    {
        $exception = $this->denialOf($this->manager(), 'posts:create', 'arn:posts:1');

        self::assertSame('This action is unauthorized.', $exception->getMessage());
    }

    /**
     * A translator without the package's line answers with the key itself; the
     * denial keeps the English message rather than showing the key.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException
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
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException
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
     * `forUser(null)` decides about a guest, which is no subject: every check
     * denies as `subject_unresolved`, the resolver is never asked who the
     * request is about, and a `for()` from the guest's manager names its
     * subject afresh.
     *
     * @return void
     */
    public function testForUserWithNoUserDecidesAboutNoSubject(): void
    {
        $principal = $this->stubAuthorizable(['posts:create']);

        $resolver = \Mockery::mock(SubjectResolver::class);
        $resolver->shouldReceive('resolve')->once()->andReturn(new Subject($principal, $principal));
        $resolver->shouldNotReceive('forUser');

        $manager = $this->managerResolving($resolver);
        $guest   = $manager->forUser(null);

        self::assertNotSame($manager, $guest);
        self::assertNull($guest->currentSubject());
        self::assertSame(DecisionReason::SUBJECT_UNRESOLVED, $guest->check('posts:create')->reason);
        self::assertSame($principal, $guest->for($principal)->currentSubject()?->subject);
        self::assertSame($principal, $manager->currentSubject()?->subject);
    }

    /**
     * The decision events carry the model the subject is about.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException
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

        $manager->check('posts:create');
        $exception = $this->denialOf($manager, 'posts:create');

        self::assertSame(DecisionReason::NO_MATCH, $exception->getReason());
    }

    /**
     * capped() returns a scoped manager whose checks are capped, leaving the
     * manager it came from uncapped; capping it again intersects the caps, and
     * a manager with no session cap resolver still applies them.
     *
     * @return void
     */
    public function testCappedReturnsAScopedManagerWhoseCapsIntersect(): void
    {
        $manager = $this->managerResolving(new StubSubjectResolver($this->stubAuthorizable(['posts:read', 'posts:edit'])));
        $capped  = $manager->capped(['posts:*']);
        $nested  = $capped->capped(['posts:read']);

        self::assertNotSame($manager, $capped);
        self::assertNotSame($capped, $nested);
        self::assertTrue($capped->can('posts:edit'));
        self::assertTrue($nested->can('posts:read'));
        self::assertTrue($manager->can('posts:edit'));

        $denied = $nested->check('posts:edit');

        self::assertSame(DecisionReason::SESSION_POLICY, $denied->reason);
        self::assertSame(DecisionStage::SESSION, $denied->stage);
        self::assertEquals(
            [
                new TraceEntry(DecisionStage::GUARDRAIL, TraceOutcome::UNCAPPED),
                new TraceEntry(DecisionStage::BOUNDARY, TraceOutcome::UNCAPPED),
                new TraceEntry(DecisionStage::SESSION, TraceOutcome::COVERED, null, [], 'capped[1]'),
                new TraceEntry(DecisionStage::SESSION, TraceOutcome::REFUSED, null, [], 'capped[2]'),
            ],
            $denied->trace,
        );
    }

    /**
     * The session cap resolver the manager is given makes each check's caps,
     * the credential's included, asked about the check's subject; without one a
     * machine is still allowed nothing, as no credential gives it scopes.
     *
     * @return void
     */
    public function testTheSessionCapResolverCapsEachCheck(): void
    {
        $machine = \Mockery::mock(AuthorizableIdentity::class, AuthorizableMachine::class);

        $machine->shouldReceive('getPermissions')->andReturn(['*']);
        $machine->shouldReceive('getPolicies')->andReturn([]);
        $machine->shouldReceive('isAuthorizationActive')->andReturn(true);

        $source = new StubSessionPolicySource(['posts:*']);
        $capped = new AuthorizationManager(
            evaluator: new PolicyEvaluator,
            subjectResolver: new StubSubjectResolver($machine),
            policyResolver: new DefaultPolicyResolver,
            lastDecisionStore: new LastDecisionStore,
            sessionCaps: new SessionCapResolver($source),
        );

        self::assertTrue($capped->can('posts:edit'));
        self::assertSame(DecisionReason::SESSION_POLICY, $capped->check('users:read')->reason);
        self::assertCount(2, $source->calls);
        self::assertSame($machine, $source->calls[0]->subject);

        $uncredentialed = $this->managerResolving(new StubSubjectResolver($machine));

        self::assertSame(DecisionReason::SESSION_POLICY, $uncredentialed->check('posts:edit')->reason);
        self::assertSame(DecisionReason::SESSION_POLICY, $uncredentialed->capped(['*'])->check('posts:edit')->reason);
    }

    /**
     * `cannot()` is the negation of `can()`, on the current subject and on
     * every scoped clone, and its decision is recorded as `check()` records it.
     *
     * @return void
     */
    public function testCannotIsTheNegationOfCan(): void
    {
        $reported  = [];
        $principal = $this->stubAuthorizable(['posts:create']);
        $manager   = $this->recordingManager($principal, $reported);

        self::assertFalse($manager->cannot('posts:create'));
        self::assertTrue($manager->cannot('posts:delete'));
        self::assertSame(DecisionReason::NO_MATCH, $manager->lastDecision()?->reason);
        self::assertTrue($manager->for($this->stubAuthorizable())->cannot('posts:create'));
        self::assertFalse($manager->forUser($principal)->cannot('posts:create'));
        self::assertTrue($manager->forUser(null)->cannot('posts:create'));
        self::assertTrue($manager->capped(['posts:delete'])->cannot('posts:create'));
        self::assertFalse($manager->withPolicies([self::allowingPolicy('posts:delete')])->cannot('posts:delete'));
        self::assertSame(['posts:create', 'posts:delete', 'posts:create', 'posts:create', 'posts:create', 'posts:create', 'posts:delete'], \array_column($reported, 'action'));
    }

    /**
     * `any()` decides each action through `check()` in the order given and is
     * allowed at the first allow, deciding no action after it; the last
     * decision is that of the action that allowed.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidCheckArgumentException
     */
    public function testAnyIsAllowedAtTheFirstAllowAndDecidesNoMore(): void
    {
        $reported = [];
        $manager  = $this->recordingManager($this->stubAuthorizable(['posts:create', 'posts:read']), $reported);

        self::assertTrue($manager->any(['posts:delete', 'posts:create', 'posts:read'], 'posts:7', ['k' => 'v']));
        self::assertSame(['posts:delete', 'posts:create'], \array_column($reported, 'action'));
        self::assertSame(['posts:7', 'posts:7'], \array_column($reported, 'resource'));
        self::assertSame([['k' => 'v'], ['k' => 'v']], \array_column($reported, 'context'));
        self::assertTrue($reported[1]['decision']->isAllowed());
        self::assertSame($reported[1]['decision'], $manager->lastDecision());
    }

    /**
     * `any()` is refused when no action is allowed, every action decided in
     * order, and the last decision is that of the last action.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidCheckArgumentException
     */
    public function testAnyIsRefusedWhenNoActionIsAllowed(): void
    {
        $reported  = [];
        $principal = $this->stubAuthorizable([], [Policy::fromArray(['name' => 'no-archiving', 'statements' => [['effect' => 'deny', 'actions' => ['posts:archive']]]])]);
        $manager   = $this->recordingManager($principal, $reported);

        self::assertFalse($manager->any(['posts:delete', 'posts:archive']));
        self::assertSame(['posts:delete', 'posts:archive'], \array_column($reported, 'action'));
        self::assertSame(DecisionReason::EXPLICIT_DENY, $manager->lastDecision()?->reason);
    }

    /**
     * `all()` decides each action through `check()` in the order given and is
     * refused at the first refusal, deciding no action after it; the last
     * decision is that of the action refused.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidCheckArgumentException
     */
    public function testAllIsRefusedAtTheFirstRefusalAndDecidesNoMore(): void
    {
        $reported = [];
        $manager  = $this->recordingManager($this->stubAuthorizable(['posts:create', 'posts:read']), $reported);

        self::assertFalse($manager->all(['posts:create', 'posts:delete', 'posts:read']));
        self::assertSame(['posts:create', 'posts:delete'], \array_column($reported, 'action'));
        self::assertSame(DecisionReason::NO_MATCH, $manager->lastDecision()?->reason);
        self::assertSame($reported[1]['decision'], $manager->lastDecision());
    }

    /**
     * `all()` is allowed when every action is allowed, each decided in order,
     * and the last decision is that of the last action.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidCheckArgumentException
     */
    public function testAllIsAllowedWhenEveryActionIsAllowed(): void
    {
        $reported = [];
        $manager  = $this->recordingManager($this->stubAuthorizable(['posts:create', 'posts:read']), $reported);

        self::assertTrue($manager->all(['posts:read', 'posts:create'], ResourceReference::record('posts', '7')));
        self::assertSame(['posts:read', 'posts:create'], \array_column($reported, 'action'));
        self::assertSame(['posts:7', 'posts:7'], \array_column($reported, 'resource'));
        self::assertSame($reported[1]['decision'], $manager->lastDecision());
    }

    /**
     * Return the checks over several actions.
     *
     * @return iterable<string, array{string, \Closure(\SineMacula\Laravel\Authorization\AuthorizationManager): bool}>
     */
    public static function severalActionChecks(): iterable
    {
        yield 'any' => ['any', static fn (AuthorizationManager $manager): bool => $manager->any([], 'posts:7')];
        yield 'all' => ['all', static fn (AuthorizationManager $manager): bool => $manager->all([], 'posts:7')];
    }

    /**
     * An empty list is refused by `any()` and `all()` before anything is
     * decided: no decision is recorded or reported, and the subject is never
     * resolved.
     *
     * @param  string  $method
     * @param  \Closure(\SineMacula\Laravel\Authorization\AuthorizationManager): bool  $decide
     * @return void
     */
    #[DataProvider('severalActionChecks')]
    public function testAnEmptyListIsRefusedBeforeAnythingIsDecided(string $method, \Closure $decide): void
    {
        $events = \Mockery::mock(Dispatcher::class);
        $events->shouldNotReceive('dispatch');

        $resolver = \Mockery::mock(SubjectResolver::class);
        $resolver->shouldNotReceive('resolve');

        $store   = new LastDecisionStore;
        $manager = new AuthorizationManager(
            evaluator: new PolicyEvaluator,
            subjectResolver: $resolver,
            policyResolver: new DefaultPolicyResolver,
            lastDecisionStore: $store,
            events: $events,
        );

        try {
            $decide($manager);
            self::fail('Expected InvalidCheckArgumentException.');
        } catch (InvalidCheckArgumentException $exception) {
            self::assertInstanceOf(\InvalidArgumentException::class, $exception);
            self::assertSame("{$method}() takes at least one action to decide, none given.", $exception->getMessage());
        }

        self::assertNull($store->get());
    }

    /**
     * `any()` and `all()` decide on every scoped clone: `for()`, `forUser()`,
     * `capped()` and `withPolicies()`, a guest refused everything.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidCheckArgumentException
     */
    public function testAnyAndAllDecideOnEveryScopedClone(): void
    {
        $reported  = [];
        $principal = $this->stubAuthorizable(['posts:create', 'posts:read']);
        $manager   = $this->recordingManager(null, $reported);

        self::assertFalse($manager->any(['posts:create']));
        self::assertTrue($manager->for($principal)->all(['posts:create', 'posts:read']));
        self::assertTrue($manager->forUser($principal)->any(['posts:delete', 'posts:read']));
        self::assertFalse($manager->forUser(null)->any(['posts:create', 'posts:read']));
        self::assertFalse($manager->for($principal)->capped(['posts:read'])->all(['posts:read', 'posts:create']));
        self::assertTrue($manager->for($principal)->capped(['posts:read'])->any(['posts:create', 'posts:read']));
        self::assertTrue($manager->for($principal)->withPolicies([self::allowingPolicy('posts:publish')])->all(['posts:publish', 'posts:read']));
        self::assertSame(DecisionReason::SESSION_POLICY, $reported[8]['decision']->reason);
        self::assertSame(DecisionReason::SUBJECT_UNRESOLVED, $reported[0]['decision']->reason);
        self::assertCount(13, $reported);
    }

    /**
     * Build a manager resolving the supplied principal, or no subject, that
     * records every decision event's action, resource, context and decision.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\AuthorizableIdentity|null  $principal
     * @param  list<array{action: string, resource: string|null, context: array<string, mixed>, decision: \SineMacula\Laravel\Authorization\Evaluation\Decision}>  $reported
     * @return \SineMacula\Laravel\Authorization\AuthorizationManager
     */
    private function recordingManager(?AuthorizableIdentity $principal, array &$reported): AuthorizationManager
    {
        $events = \Mockery::mock(Dispatcher::class);
        $events->shouldReceive('dispatch')
            ->andReturnUsing(static function (DecisionEvaluated $event) use (&$reported): void {
                $reported[] = ['action' => $event->action, 'resource' => $event->resource, 'context' => $event->context, 'decision' => $event->decision];
            });

        return new AuthorizationManager(
            evaluator: new PolicyEvaluator,
            subjectResolver: new StubSubjectResolver($principal),
            policyResolver: new DefaultPolicyResolver,
            lastDecisionStore: new LastDecisionStore,
            events: $events,
        );
    }

    /**
     * Return a policy allowing the action.
     *
     * @param  string  $action
     * @return \SineMacula\Laravel\Authorization\Evaluation\Policy
     */
    private static function allowingPolicy(string $action): Policy
    {
        return Policy::fromArray(['name' => 'allowing', 'statements' => [['effect' => 'allow', 'actions' => [$action]]]]);
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
     * Build a manager gathering policies through the supplied policy resolver
     * and resolving its subject through the supplied subject resolver.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\PolicyResolver  $policies
     * @param  \SineMacula\Laravel\Authorization\Contracts\SubjectResolver  $subjects
     * @return \SineMacula\Laravel\Authorization\AuthorizationManager
     */
    private function managerWithPolicies(PolicyResolver $policies, SubjectResolver $subjects): AuthorizationManager
    {
        return new AuthorizationManager(
            evaluator: new PolicyEvaluator,
            subjectResolver: $subjects,
            policyResolver: $policies,
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
     * Return an authentication context that supplies nothing.
     *
     * @return \SineMacula\Laravel\Authorization\Contracts\AuthenticationContext
     */
    private static function authentication(): AuthenticationContext
    {
        return new class implements AuthenticationContext {
            /**
             * Return the namespaces the context supplies.
             *
             * @return list<string>
             */
            #[\Override]
            public function namespaces(): array
            {
                return ['authentication'];
            }

            /**
             * Return no values.
             *
             * @return array<string, array<string, mixed>>
             */
            #[\Override]
            public function values(): array
            {
                return [];
            }
        };
    }

    /**
     * Return an environment context that supplies nothing.
     *
     * @return \SineMacula\Laravel\Authorization\Contracts\EnvironmentContext
     */
    private static function environment(): EnvironmentContext
    {
        return new class implements EnvironmentContext {
            /**
             * Return no values.
             *
             * @return array<string, mixed>
             */
            #[\Override]
            public function values(): array
            {
                return [];
            }
        };
    }

    /**
     * Run `authorize()` and return the denial it raises.
     *
     * @param  \SineMacula\Laravel\Authorization\AuthorizationManager  $manager
     * @param  string  $action
     * @param  string|null  $resource
     * @return \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException
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
     * and policies, active unless told otherwise.
     *
     * @param  array<int, string>  $permissions
     * @param  array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>  $policies
     * @param  bool  $active
     * @return \SineMacula\Laravel\Authorization\Contracts\AuthorizableIdentity
     */
    private function stubAuthorizable(array $permissions = [], array $policies = [], bool $active = true): AuthorizableIdentity
    {
        $principal = \Mockery::mock(AuthorizableIdentity::class);

        $principal->shouldReceive('getPermissions')
            ->andReturn($permissions);

        $principal->shouldReceive('getPolicies')
            ->andReturn($policies);

        $principal->shouldReceive('isAuthorizationActive')
            ->andReturn($active);

        return $principal;
    }

    /**
     * Return the steps the guardrail, boundary and session stages add, in that
     * order, when none of them caps the check.
     *
     * @return list<\SineMacula\Laravel\Authorization\Evaluation\TraceEntry>
     */
    private static function uncapped(): array
    {
        return [
            new TraceEntry(DecisionStage::GUARDRAIL, TraceOutcome::UNCAPPED),
            new TraceEntry(DecisionStage::BOUNDARY, TraceOutcome::UNCAPPED),
            new TraceEntry(DecisionStage::SESSION, TraceOutcome::UNCAPPED),
        ];
    }
}
