<?php

declare(strict_types = 1);

namespace Benchmarks\Runtime;

use PhpBench\Attributes as Bench;
use SineMacula\Laravel\Authorization\Evaluation\Policy;
use SineMacula\Laravel\Authorization\Evaluation\PolicyEvaluator;

/**
 * PHPBench micro-benchmark for the IAM 4-step evaluator.
 *
 * Exercises the three most common decision paths: implicit deny on an
 * empty policy, explicit allow, and explicit deny overriding a prior
 * allow.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class PolicyEvaluatorBench
{
    /**
     * Evaluator instance used across revolutions.
     */
    private PolicyEvaluator $evaluator;

    /**
     * Policy with an explicit allow on `posts:create`.
     */
    private Policy $allowPolicy;

    /**
     * Policy with both an allow and a deny on `posts:delete`.
     */
    private Policy $denyPolicy;

    /**
     * Prepare fixtures shared across every benchmark iteration.
     *
     * @return void
     */
    #[Bench\BeforeMethods('setUp')]
    public function __construct() {}

    /**
     * Bench setUp — builds the reusable policy fixtures.
     *
     * @return void
     */
    public function setUp(): void
    {
        $this->evaluator = new PolicyEvaluator();

        $this->allowPolicy = Policy::fromArray([
            'name'       => 'allow',
            'statements' => [['effect' => 'allow', 'actions' => ['posts:create']]],
        ]);

        $this->denyPolicy = Policy::fromArray([
            'name'       => 'deny',
            'statements' => [
                ['effect' => 'allow', 'actions' => ['posts:delete']],
                ['effect' => 'deny',  'actions' => ['posts:delete']],
            ],
        ]);
    }

    /**
     * Benchmark: evaluator with no policies.
     *
     * @return void
     */
    #[Bench\Revs(1000)]
    #[Bench\Iterations(3)]
    #[Bench\BeforeMethods('setUp')]
    public function benchImplicitDeny(): void
    {
        $this->evaluator->evaluate([], 'posts:create');
    }

    /**
     * Benchmark: evaluator with a single allow.
     *
     * @return void
     */
    #[Bench\Revs(1000)]
    #[Bench\Iterations(3)]
    #[Bench\BeforeMethods('setUp')]
    public function benchExplicitAllow(): void
    {
        $this->evaluator->evaluate([$this->allowPolicy], 'posts:create');
    }

    /**
     * Benchmark: evaluator where deny overrides allow.
     *
     * @return void
     */
    #[Bench\Revs(1000)]
    #[Bench\Iterations(3)]
    #[Bench\BeforeMethods('setUp')]
    public function benchDenyOverridesAllow(): void
    {
        $this->evaluator->evaluate([$this->denyPolicy], 'posts:delete');
    }
}
