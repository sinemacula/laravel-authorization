<?php

declare(strict_types = 1);

namespace Tests\Performance;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Enums\PolicyEffect;
use SineMacula\Laravel\Authorization\Evaluation\ConditionEvaluator;
use SineMacula\Laravel\Authorization\Evaluation\Statement;

/**
 * Performance budget for `Statement::evaluateConditions()`.
 *
 * Conditions are the heaviest per-statement work the evaluator does.
 * The full 18-operator surface (string, numeric, temporal, set,
 * boolean, null, CIDR) is exercised in one chain to guard against
 * drift in any individual arm — a regression in a single operator
 * moves the aggregate enough to trip the budget well before it
 * affects a production workload.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConditionEvaluator::class)]
#[CoversClass(Statement::class)]
final class ConditionEvaluationBudgetTest extends TestCase
{
    /**
     * Evaluating an 18-operator condition chain 1,000 times must
     * complete in under half a second on the reference machine.
     * Observed ~55μs per call on the reference machine (≈55ms
     * total); budget is ~10× to tolerate CI variance.
     *
     * @return void
     */
    public function testCanEvaluateFullOperatorChainQuickly(): void
    {
        $statement = new Statement(
            effect: PolicyEffect::ALLOW,
            actions: ['*'],
            conditions: self::buildConditionChain(),
        );
        $context = self::buildContext();

        $start = \microtime(true);

        for ($i = 0; $i < 1000; $i++) {
            $statement->evaluateConditions($context);
        }

        $elapsed = \microtime(true) - $start;

        self::assertLessThan(
            0.5,
            $elapsed,
            "Statement::evaluateConditions() budget exceeded ({$elapsed}s for 1,000 iterations of an 18-operator chain).",
        );
    }

    /**
     * Build the 18-operator condition chain — every branch in
     * `Statement::evaluateOperator()` appears exactly once. Kept
     * here rather than in a shared helper so the performance suite
     * has no runtime dependency on the benchmark-support tree.
     *
     * @return array<string, mixed>
     */
    private static function buildConditionChain(): array
    {
        return [
            'tenant'       => ['eq' => 'tenant-99'],
            'role'         => ['neq' => 'guest'],
            'country'      => ['in' => ['US', 'GB', 'CA']],
            'blocklist'    => ['not_in' => ['blocked', 'banned']],
            'ip'           => ['cidr' => '10.0.0.0/8'],
            'path'         => ['starts_with' => '/admin'],
            'file'         => ['ends_with' => '.json'],
            'scheduled_at' => ['before' => '2099-01-01T00:00:00Z'],
            'created_at'   => ['after' => '2000-01-01T00:00:00Z'],
            'window'       => ['between' => ['2000-01-01T00:00:00Z', '2099-01-01T00:00:00Z']],
            'agent'        => ['string_like' => 'Mozilla/*'],
            'deleted_at'   => ['null' => true],
            'email'        => ['not_null' => true],
            'age'          => ['gt' => 17],
            'quota'        => ['gte' => 0],
            'strikes'      => ['lt' => 3],
            'priority'     => ['lte' => 10],
            'verified'     => ['bool' => true],
        ];
    }

    /**
     * Build the matching context — every operator resolves truthy
     * so the full chain runs to completion.
     *
     * @return array<string, mixed>
     */
    private static function buildContext(): array
    {
        return [
            'tenant'       => 'tenant-99',
            'role'         => 'member',
            'country'      => 'US',
            'blocklist'    => 'allowed',
            'ip'           => '10.0.0.42',
            'path'         => '/admin/posts',
            'file'         => 'report.json',
            'scheduled_at' => '2026-06-01T00:00:00Z',
            'created_at'   => '2026-01-01T00:00:00Z',
            'window'       => '2026-06-01T00:00:00Z',
            'agent'        => 'Mozilla/5.0',
            'deleted_at'   => null,
            'email'        => 'alice@example.test',
            'age'          => 42,
            'quota'        => 10,
            'strikes'      => 0,
            'priority'     => 5,
            'verified'     => true,
        ];
    }
}
