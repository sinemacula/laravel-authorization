<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Contracts\PolicyResolver;
use SineMacula\Laravel\Authorization\Contracts\PolicyStore;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\LastDecisionStore;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Evaluation\StatementReference;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Policy as PolicyModel;
use SineMacula\Laravel\Authorization\Resolvers\DefaultPolicyResolver;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubSubjectResolver;
use Tests\TestCase;

/**
 * Feature coverage for the `PolicyResolver` seam and the `LastDecisionStore` /
 * `Authorization::lastDecision()` surface.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(DefaultPolicyResolver::class)]
#[CoversClass(LastDecisionStore::class)]
#[CoversClass(AuthorizationManager::class)]
final class PolicyResolverAndLastDecisionStoreTest extends TestCase
{
    /**
     * `DefaultPolicyResolver` returns the principal's attached policies when no
     * external store is configured.
     *
     * @return void
     */
    public function testDefaultResolverReturnsPrincipalPolicies(): void
    {
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $user->attachPolicy(PolicyModel::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'allow-x',
            'document' => [
                'statements' => [['effect' => 'allow', 'actions' => ['x']]],
            ],
        ]));

        $resolver = new DefaultPolicyResolver;

        $policies = $resolver->policiesFor($user->fresh());

        self::assertCount(1, $policies);
        self::assertSame('allow-x', $policies[0]->name);
    }

    /**
     * `DefaultPolicyResolver` unions the store's policies with the principal's
     * attached policies.
     *
     * @return void
     */
    public function testDefaultResolverUnionsStoreWithPrincipalPolicies(): void
    {
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $user->attachPolicy(PolicyModel::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'principal-side',
            'document' => [
                'statements' => [['effect' => 'allow', 'actions' => ['x']]],
            ],
        ]));

        $storePolicy = EvaluationPolicy::fromArray([
            'name'       => 'store-side',
            'statements' => [['effect' => 'allow', 'actions' => ['y']]],
        ]);

        /**
         * Anonymous policy store returning the captured policy.
         */
        $store = new class ($storePolicy) implements PolicyStore {
            /**
             * Create a new store wrapping a fixed policy.
             *
             * @param  \SineMacula\Laravel\Authorization\Evaluation\Policy  $policy
             * @return void
             */
            public function __construct(

                /** The policy returned for every principal. */
                private readonly EvaluationPolicy $policy,
            ) {}

            /**
             * Return the captured policy for the supplied principal.
             *
             * @param  object  $principal
             * @return array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>
             */
            #[\Override]
            public function policiesFor(object $principal): array
            {
                return [$this->policy];
            }
        };

        $resolver = new DefaultPolicyResolver(store: $store);

        $policies = $resolver->policiesFor($user->fresh());
        $names    = \array_map(static fn (EvaluationPolicy $policy): string => $policy->name, $policies);

        self::assertCount(2, $policies);
        self::assertContains('store-side', $names);
        self::assertContains('principal-side', $names);
    }

    /**
     * Binding a custom `PolicyResolver` swaps the gathering strategy — the
     * manager never hits the Eloquent layer when the resolver returns a fixed
     * list.
     *
     * @return void
     */
    public function testCustomResolverOverridesTheGatheringStrategy(): void
    {
        $fixed = EvaluationPolicy::fromArray([
            'name'       => 'fixed',
            'statements' => [['effect' => 'allow', 'actions' => ['fixed:act']]],
        ]);

        $this->app->instance(PolicyResolver::class, new class ($fixed) implements PolicyResolver { // @phpstan-ignore method.nonObject

            /**
             * Create a new resolver wrapping a fixed policy.
             *
             * @param  \SineMacula\Laravel\Authorization\Evaluation\Policy  $policy
             * @return void
             */
            public function __construct(

                /** The policy returned for every principal. */
                private readonly EvaluationPolicy $policy,
            ) {}

            /**
             * Return the captured policy for the supplied principal.
             *
             * @param  object  $principal
             * @return array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>
             */
            #[\Override]
            public function policiesFor(object $principal): array
            {
                return [$this->policy];
            }
        });

        $this->app->forgetInstance('authorization'); // @phpstan-ignore method.nonObject
        $this->app->forgetInstance(AuthorizationManager::class); // @phpstan-ignore method.nonObject

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);

        $decision = Authorization::for($user)->check('fixed:act');

        self::assertTrue($decision->isAllowed());
        self::assertSame(DecisionStage::ALLOW, $decision->stage);
        self::assertEquals([new StatementReference('fixed', 0)], $decision->statements);
    }

    /**
     * `Authorization::lastDecision()` returns the most recent decision even
     * when it was produced by a scoped clone via `for()`.
     *
     * @return void
     */
    public function testLastDecisionSurfacesScopedEvaluation(): void
    {
        $user = $this->bindResolvableUser();

        $user->attachPolicy(PolicyModel::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'deny-edit',
            'document' => [
                'statements' => [['effect' => 'deny', 'actions' => ['posts:edit']]],
            ],
        ]));

        self::assertNull(Authorization::lastDecision());

        Authorization::for($user)->can('posts:edit');

        $last = Authorization::lastDecision();

        self::assertNotNull($last); // @phpstan-ignore staticMethod.impossibleType
        self::assertFalse($last->isAllowed());
        self::assertSame(DecisionReason::EXPLICIT_DENY, $last->reason);
        self::assertSame(DecisionStage::DENY, $last->stage);
    }

    /**
     * `Authorization::lastDecision()` survives `withPolicies()` scoping too —
     * the store is shared across every clone.
     *
     * @return void
     */
    public function testLastDecisionSurfacesWithPoliciesEvaluation(): void
    {
        $user = $this->bindResolvableUser();

        $override = EvaluationPolicy::fromArray([
            'name'       => 'override',
            'statements' => [['effect' => 'allow', 'actions' => ['probe']]],
        ]);

        Authorization::for($user)->withPolicies([$override])->can('probe');

        $last = Authorization::lastDecision();

        self::assertNotNull($last);
        self::assertTrue($last->isAllowed());
        self::assertNull($last->reason);
        self::assertEquals([new StatementReference('override', 0)], $last->statements);
    }

    /**
     * `forgetLastDecision()` clears the store mid-request, so a later read does
     * not see an earlier decision.
     *
     * @return void
     */
    public function testForgetLastDecisionClearsTheStore(): void
    {
        $user = $this->bindResolvableUser();

        Authorization::for($user)->can('any:thing');

        self::assertNotNull(Authorization::lastDecision());

        Authorization::forgetLastDecision();

        self::assertNull(Authorization::lastDecision());
    }

    /**
     * The store's `reset()` alias clears the slot the same way `forget()` does.
     *
     * @return void
     */
    public function testResetClearsTheStore(): void
    {
        $store = new LastDecisionStore;
        $store->put(Decision::allow(DecisionStage::ALLOW));

        self::assertNotNull($store->get());

        $store->reset();

        self::assertNull($store->get());
    }

    /**
     * `Authorization::explain()` returns the same human-readable summary that
     * `Decision::explain()` produces for the check, the verdict with its
     * reason, stage and deciding statement followed by each step of the trace —
     * the shortcut exists so error-handler output and the CLI path can stay
     * terse.
     *
     * @return void
     */
    public function testExplainShortcutReturnsHumanReadableDecision(): void
    {
        $user = $this->bindResolvableUser();

        $user->attachPolicy(PolicyModel::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'deny-destruct',
            'document' => [
                'statements' => [['effect' => 'deny', 'actions' => ['posts:destroy']]],
            ],
        ]));

        $explanation = Authorization::for($user)->explain('posts:destroy');

        self::assertSame(
            "DENY (explicit_deny: an applicable statement denies it) at the deny stage by deny-destruct#0.\n"
            . '  [deny] deny-destruct#0: matched',
            $explanation,
        );
        self::assertSame(Authorization::for($user)->check('posts:destroy')->explain(), $explanation);
    }

    /**
     * Bind a subject resolver that returns a freshly-created StubIdentity so
     * the facade picks it up via the configured resolver.
     *
     * @return \Tests\Feature\Stubs\StubIdentity
     */
    private function bindResolvableUser(): StubIdentity
    {
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);

        $resolver = new StubSubjectResolver($user);

        $this->app->instance(SubjectResolver::class, $resolver); // @phpstan-ignore method.nonObject
        $this->app->forgetInstance('authorization'); // @phpstan-ignore method.nonObject
        $this->app->forgetInstance(AuthorizationManager::class); // @phpstan-ignore method.nonObject

        return $user;
    }
}
