<?php

declare(strict_types = 1);

namespace Tests\Performance;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\Policy;
use SineMacula\Laravel\Authorization\Evaluation\PolicyEvaluator;
use SineMacula\Laravel\Authorization\Evaluation\PolicyLimits;
use Tests\Concerns\MeasuresTime;

/**
 * Performance tests codifying lightweight budgets on the evaluator hot path.
 *
 * Budgets are deliberately loose — the suite's job is to stop catastrophic
 * regressions, not to benchmark CPU throughput (the PHPBench suite handles
 * that).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(PolicyEvaluator::class)]
final class EvaluatorThroughputTest extends TestCase
{
    use MeasuresTime;

    /**
     * The evaluator can walk a 100-statement policy 1,000 times in under half a
     * second on a reference machine.
     *
     * @return void
     */
    public function testCanEvaluateManyStatementsQuickly(): void
    {
        $statements = [];

        for ($i = 0; $i < 100; $i++) {
            $statements[] = ['effect' => 'allow', 'actions' => ["permission:{$i}"]];
        }

        $policy    = Policy::fromArray(['name' => 'bulk', 'statements' => $statements]);
        $evaluator = new PolicyEvaluator;

        $start = microtime(true);

        for ($i = 0; $i < 1000; $i++) {
            $evaluator->evaluate([$policy], 'permission:50');
        }

        $elapsed = microtime(true) - $start;

        $this->assertWithinBudget(0.5, $elapsed, "Evaluator budget exceeded ({$elapsed}s).");
    }

    /**
     * A policy at the statement and condition limits, every statement naming
     * the action but only the last one's conditions holding, is evaluated 10
     * times in under 1.5s. It is larger than the default byte limit admits, so
     * it bounds every admissible policy.
     *
     * @return void
     */
    public function testCanEvaluateAPolicyAtTheStatementAndConditionLimitsQuickly(): void
    {
        $limits = new PolicyLimits;
        $values = \array_fill_keys(\array_map(static fn (int $i): string => "k{$i}", \range(1, $limits->conditions)), 'v');
        $tests  = \array_combine(\array_map(static fn (string $key): string => "input.{$key}", \array_keys($values)), $values);
        $missed = ['effect' => 'allow', 'actions' => ['posts:read'], 'conditions' => ['eq' => [...$tests, "input.k{$limits->conditions}" => 'x']]];

        $statements   = \array_fill(0, $limits->statements - 1, $missed);
        $statements[] = ['effect' => 'allow', 'actions' => ['posts:read'], 'conditions' => ['eq' => $tests]];

        $policy    = Policy::fromArray(['name' => 'limits', 'statements' => $statements]);
        $context   = ['input' => $values];
        $evaluator = new PolicyEvaluator;

        self::assertTrue($evaluator->evaluate([$policy], 'posts:read', null, $context)->isAllowed());
        self::assertFalse($evaluator->evaluate([$policy], 'posts:read', null, ['input' => [...$values, "k{$limits->conditions}" => 'y']])->isAllowed());

        $elapsed = $this->fastestOf(3, static function () use ($evaluator, $policy, $context): void {
            for ($i = 0; $i < 10; $i++) {
                $evaluator->evaluate([$policy], 'posts:read', null, $context);
            }
        });

        $this->assertWithinBudget(1.5, $elapsed, "Evaluator budget at the policy limits exceeded ({$elapsed}s for 10 checks).");
    }
}
