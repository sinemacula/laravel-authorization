<?php

declare(strict_types = 1);

namespace Tests\Performance;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\ConditionEvaluator;
use SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect;
use SineMacula\Laravel\Authorization\Evaluation\Statement;

/**
 * Performance budget for `Statement::conditionsSatisfiedBy()`.
 *
 * Conditions are the heaviest per-statement work the evaluator does. The full
 * 20-operator surface (string, numeric, temporal, set, boolean, null, IP range,
 * multi-valued) is exercised in one chain to guard against drift in any
 * individual arm — a regression in a single operator moves the aggregate enough
 * to trip the budget well before it affects a production workload.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(ConditionEvaluator::class)]
#[CoversClass(Statement::class)]
final class ConditionEvaluationBudgetTest extends TestCase
{
    /**
     * Evaluating a 20-operator condition chain 1,000 times must complete in
     * under half a second on the reference machine. Observed ~55μs per call on
     * the reference machine (≈55ms total); budget is ~10× to tolerate CI
     * variance.
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

        self::assertTrue($statement->conditionsSatisfiedBy($context));

        $start = \microtime(true);

        for ($i = 0; $i < 1000; $i++) {
            $statement->conditionsSatisfiedBy($context);
        }

        $elapsed = \microtime(true) - $start;

        self::assertLessThan(
            0.5,
            $elapsed,
            "Statement::conditionsSatisfiedBy() budget exceeded ({$elapsed}s for 1,000 iterations of a 20-operator chain).",
        );
    }

    /**
     * Build the 20-operator condition chain — every operator of
     * `ConditionEvaluator` appears exactly once. Kept here rather than in a
     * shared helper so the performance suite has no runtime dependency on the
     * benchmark-support tree.
     *
     * @return array<string, mixed>
     */
    private static function buildConditionChain(): array
    {
        return [
            'eq'            => ['tenant' => 'tenant-99'],
            'neq'           => ['role' => 'guest'],
            'in'            => ['country' => ['US', 'GB', 'CA']],
            'not_in'        => ['blocklist' => ['blocked', 'banned']],
            'starts_with'   => ['path' => '/admin'],
            'ends_with'     => ['file' => '.json'],
            'like'          => ['agent' => 'Mozilla/*'],
            'gt'            => ['age' => 17],
            'gte'           => ['quota' => 0],
            'lt'            => ['strikes' => 3],
            'lte'           => ['priority' => 10],
            'before'        => ['scheduled_at' => '2099-01-01T00:00:00Z'],
            'after'         => ['created_at' => '2000-01-01T00:00:00Z'],
            'between'       => ['window' => ['2000-01-01T00:00:00Z', '2099-01-01T00:00:00Z']],
            'bool'          => ['verified' => true],
            'null'          => ['deleted_at' => true, 'email' => false],
            'ip_in'         => ['ip' => '10.0.0.0/8'],
            'ip_not_in'     => ['ip' => ['192.168.0.0/16', '2001:db8::/32']],
            'any_value_in'  => ['groups' => ['admins', 'editors']],
            'all_values_in' => ['scopes' => ['posts:read', 'posts:write', 'posts:delete']],
        ];
    }

    /**
     * Build the matching context — every operator resolves truthy so the full
     * chain runs to completion.
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
            'groups'       => ['members', 'editors'],
            'scopes'       => ['posts:read', 'posts:write'],
        ];
    }
}
