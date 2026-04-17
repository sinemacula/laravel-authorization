<?php

declare(strict_types = 1);

namespace Tests\Performance;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\Policy;
use SineMacula\Laravel\Authorization\Evaluation\PolicyEvaluator;

/**
 * Performance tests codifying lightweight budgets on the evaluator
 * hot path.
 *
 * Budgets are deliberately loose — the suite's job is to stop
 * catastrophic regressions, not to benchmark CPU throughput (the
 * PHPBench suite handles that).
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
    /**
     * The evaluator can walk a 100-statement policy 1,000 times in
     * under half a second on a reference machine.
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

        self::assertLessThan(0.5, $elapsed, "Evaluator budget exceeded ({$elapsed}s).");
    }
}
