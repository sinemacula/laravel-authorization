<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Contracts\PolicyRepository;
use SineMacula\Laravel\Authorization\Contracts\PolicyStore;
use SineMacula\Laravel\Authorization\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authorization\DecisionJournal;
use SineMacula\Laravel\Authorization\Evaluation\EvaluationResult;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Policy as PolicyModel;
use SineMacula\Laravel\Authorization\Repositories\DefaultPolicyRepository;
use Tests\Feature\Stubs\StubAuthorizable;
use Tests\TestCase;

/**
 * Feature coverage for the `PolicyRepository` seam and the
 * `DecisionJournal` / `Authorization::lastDecision()` surface.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DefaultPolicyRepository::class)]
#[CoversClass(DecisionJournal::class)]
#[CoversClass(AuthorizationManager::class)]
final class PolicyRepositoryAndJournalTest extends TestCase
{
    /**
     * `DefaultPolicyRepository` returns the principal's attached
     * policies when no external store is configured.
     *
     * @return void
     */
    public function testDefaultRepositoryReturnsPrincipalPolicies(): void
    {
        $user = StubAuthorizable::create(['id' => (string) Str::uuid()]);
        $user->attachPolicy(PolicyModel::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'allow-x',
            'document' => [
                'statements' => [['effect' => 'allow', 'actions' => ['x']]],
            ],
        ]));

        $repository = new DefaultPolicyRepository;

        $policies = $repository->policiesFor($user->fresh());

        self::assertCount(1, $policies);
        self::assertSame('allow-x', $policies[0]->name);
    }

    /**
     * `DefaultPolicyRepository` unions the store's policies with
     * the principal's attached policies.
     *
     * @return void
     */
    public function testDefaultRepositoryUnionsStoreWithPrincipalPolicies(): void
    {
        $user = StubAuthorizable::create(['id' => (string) Str::uuid()]);
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

        $store = new class ($storePolicy) implements PolicyStore {
            public function __construct(private readonly EvaluationPolicy $policy) {}

            public function policiesFor(object $principal): array
            {
                return [$this->policy];
            }
        };

        $repository = new DefaultPolicyRepository(store: $store);

        $policies = $repository->policiesFor($user->fresh());
        $names    = \array_map(static fn (EvaluationPolicy $policy): string => $policy->name, $policies);

        self::assertCount(2, $policies);
        self::assertContains('store-side', $names);
        self::assertContains('principal-side', $names);
    }

    /**
     * Binding a custom `PolicyRepository` swaps the gathering
     * strategy — the manager never hits the Eloquent layer when
     * the repository returns a fixed list.
     *
     * @return void
     */
    public function testCustomRepositoryOverridesTheGatheringStrategy(): void
    {
        $fixed = EvaluationPolicy::fromArray([
            'name'       => 'fixed',
            'statements' => [['effect' => 'allow', 'actions' => ['fixed:act']]],
        ]);

        $this->app->instance(PolicyRepository::class, new class ($fixed) implements PolicyRepository {
            public function __construct(private readonly EvaluationPolicy $policy) {}

            public function policiesFor(object $principal): array
            {
                return [$this->policy];
            }
        });

        $this->app->forgetInstance('authorization');
        $this->app->forgetInstance(AuthorizationManager::class);

        $user = StubAuthorizable::create(['id' => (string) Str::uuid()]);

        $result = Authorization::for($user)->evaluate('fixed:act');

        self::assertTrue($result->allowed);
        self::assertSame(EvaluationResult::REASON_EXPLICIT_ALLOW, $result->reason);
    }

    /**
     * `Authorization::lastDecision()` returns the most recent
     * evaluation result even when the decision was produced by a
     * scoped clone via `for()`.
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

        self::assertNotNull($last);
        self::assertFalse($last->allowed);
        self::assertSame(EvaluationResult::REASON_EXPLICIT_DENY, $last->reason);
    }

    /**
     * `Authorization::lastDecision()` survives `withPolicies()`
     * scoping too — the journal is shared across every clone.
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
        self::assertTrue($last->allowed);
        self::assertSame(EvaluationResult::REASON_EXPLICIT_ALLOW, $last->reason);
    }

    /**
     * `forgetLastDecision()` clears the journal so long-running
     * workers can reset between requests without a stale decision
     * leaking through.
     *
     * @return void
     */
    public function testForgetLastDecisionClearsTheJournal(): void
    {
        $user = $this->bindResolvableUser();

        Authorization::for($user)->can('any:thing');

        self::assertNotNull(Authorization::lastDecision());

        Authorization::forgetLastDecision();

        self::assertNull(Authorization::lastDecision());
    }

    /**
     * `Authorization::explain()` returns the same human-readable
     * summary that the trace-aware `EvaluationResult::explain()`
     * produces — the shortcut exists so error-handler output and
     * the CLI path can stay terse.
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

        self::assertStringContainsString('DENY', $explanation);
        self::assertStringContainsString('explicit deny', $explanation);
    }

    /**
     * Bind a principal resolver that returns a freshly-created
     * StubAuthorizable so the facade picks it up via the configured
     * resolver.
     *
     * @return \Tests\Feature\Stubs\StubAuthorizable
     */
    private function bindResolvableUser(): StubAuthorizable
    {
        $user = StubAuthorizable::create(['id' => (string) Str::uuid()]);

        $resolver = new class ($user) implements PrincipalResolver {
            public function __construct(private readonly object $user) {}

            public function resolve(): ?object
            {
                return $this->user;
            }
        };

        $this->app->instance(PrincipalResolver::class, $resolver);
        $this->app->forgetInstance('authorization');
        $this->app->forgetInstance(AuthorizationManager::class);

        return $user;
    }
}
