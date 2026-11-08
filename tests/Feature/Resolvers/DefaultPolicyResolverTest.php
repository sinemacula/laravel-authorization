<?php

declare(strict_types = 1);

namespace Tests\Feature\Resolvers;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Contracts\PolicyStore;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\Enums\GrantSource;
use SineMacula\Laravel\Authorization\Evaluation\EvidenceRecorder;
use SineMacula\Laravel\Authorization\Evaluation\GrantProvenance;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Evaluation\StatementReference;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Resolvers\DefaultPolicyResolver;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for the default policy resolver's explained resolution: the
 * policies `policiesFor()` gives, each noted with where it came from.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DefaultPolicyResolver::class)]
final class DefaultPolicyResolverTest extends TestCase
{
    /**
     * The explained resolution gives the store's policies and the principal's
     * own, as `policiesFor()` does, noting the store's as unavailable and the
     * principal's by their attachment.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheExplainedPoliciesAreTheResolvedOnesWithTheirProvenance(): void
    {
        $user     = StubIdentity::create(['id' => 'user-1']);
        $own      = Policy::create(['name' => 'own', 'document' => ['statements' => [['effect' => 'allow', 'actions' => ['posts:read']]]]]);
        $coded    = EvaluationPolicy::fromArray(['name' => 'coded', 'statements' => [['effect' => 'allow', 'actions' => ['posts:edit']]]]);
        $resolver = new DefaultPolicyResolver(self::store($coded));
        $recorder = new EvidenceRecorder;

        $user->attachPolicy($own);

        $explained = $resolver->explainedPoliciesFor($user, $recorder);
        $names     = static fn (array $policies): array => \array_map(static fn (EvaluationPolicy $policy): string => $policy->name, $policies);

        self::assertSame($names($resolver->policiesFor($user)), $names($explained));
        self::assertSame([0, 1], \array_keys($explained));
        self::assertEquals(
            [GrantProvenance::unavailable('coded'), new GrantProvenance(GrantSource::POLICY, "own[{$own->id}]", Reference::of($user), false, [], true)],
            $recorder->evidenceFor(Decision::allow(DecisionStage::ALLOW, [new StatementReference('coded', 0), new StatementReference('own', 0, $own->id)]))->grants,
        );
    }

    /**
     * A principal that is no identity gets the store's policies alone, and a
     * resolver without a store gives an identity its own alone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWhatEachPrincipalGets(): void
    {
        $coded = EvaluationPolicy::fromArray(['name' => 'coded', 'statements' => [['effect' => 'allow', 'actions' => ['posts:edit']]]]);

        self::assertSame([$coded], (new DefaultPolicyResolver(self::store($coded)))->explainedPoliciesFor(new \stdClass, new EvidenceRecorder));
        self::assertSame([], (new DefaultPolicyResolver)->explainedPoliciesFor(StubIdentity::create(['id' => 'user-1']), new EvidenceRecorder));
    }

    /**
     * Return a store giving the policy to every principal.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Policy  $policy
     * @return \SineMacula\Laravel\Authorization\Contracts\PolicyStore
     */
    private static function store(EvaluationPolicy $policy): PolicyStore
    {
        return new class ($policy) implements PolicyStore {
            /**
             * Create a store giving the policy.
             *
             * @param  \SineMacula\Laravel\Authorization\Evaluation\Policy  $policy
             */
            public function __construct(

                /** The policy given. */
                private readonly EvaluationPolicy $policy,
            ) {}

            /**
             * Return the policy.
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
    }
}
