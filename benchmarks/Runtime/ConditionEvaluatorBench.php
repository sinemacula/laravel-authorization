<?php

declare(strict_types = 1);

namespace Benchmarks\Runtime;

use Benchmarks\Support\BenchmarkFixtures;
use PhpBench\Attributes as Bench;
use SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect;
use SineMacula\Laravel\Authorization\Evaluation\Statement;

/**
 * PHPBench micro-benchmark for the statement condition evaluator.
 *
 * Conditions are the heaviest per-statement work the evaluator does: every
 * matching statement walks its condition map and dispatches each operator
 * through `ConditionEvaluator::evaluate()`. The bench carves the 20-operator
 * surface into four natural classes so drift in any single arm shows up under
 * its own subject:
 *
 * - string ops — `eq`, `neq`, `starts_with`, `ends_with`, `like`;
 * - numeric ops — `gt`, `gte`, `lt`, `lte`;
 * - temporal ops — `before`, `after`, `between`;
 * - set ops — `in`, `not_in`, `bool`, `null`, `ip_in`, `ip_not_in`,
 *   `any_value_in`, `all_values_in`.
 *
 * A fifth subject runs the full 20-operator chain so the matching budget test
 * has a direct comparator.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[Bench\OutputTimeUnit('microseconds')]
final class ConditionEvaluatorBench
{
    /** @var \SineMacula\Laravel\Authorization\Evaluation\Statement Statement covering string operators. */
    private Statement $stringStatement; // @phpstan-ignore property.uninitialized

    /** @var \SineMacula\Laravel\Authorization\Evaluation\Statement Statement covering numeric operators. */
    private Statement $numericStatement; // @phpstan-ignore property.uninitialized

    /** @var \SineMacula\Laravel\Authorization\Evaluation\Statement Statement covering temporal operators. */
    private Statement $temporalStatement; // @phpstan-ignore property.uninitialized

    /** @var \SineMacula\Laravel\Authorization\Evaluation\Statement Statement covering set / boolean / null / IP range operators. */
    private Statement $setStatement; // @phpstan-ignore property.uninitialized

    /** @var \SineMacula\Laravel\Authorization\Evaluation\Statement Statement running the full 20-operator chain in one pass. */
    private Statement $fullStatement; // @phpstan-ignore property.uninitialized

    /** @var array<string, mixed> Matching context reused across revolutions. */
    private array $context = [];

    /**
     * Bench setUp — materialise the five statement fixtures once per iteration
     * so revolution cost measures only `conditionsSatisfiedBy()`.
     *
     * @return void
     */
    public function setUp(): void
    {
        $this->context = BenchmarkFixtures::conditionContext();

        $this->stringStatement   = self::buildStringStatement();
        $this->numericStatement  = self::buildNumericStatement();
        $this->temporalStatement = self::buildTemporalStatement();
        $this->setStatement      = self::buildSetStatement();
        $this->fullStatement     = self::buildFullStatement();
    }

    /**
     * Benchmark: string operators (`eq`, `neq`, `starts_with`, `ends_with`,
     * `like`).
     *
     * @return void
     */
    #[Bench\BeforeMethods('setUp')]
    #[Bench\Iterations(3)]
    #[Bench\Revs(5000)]
    public function benchStringOperators(): void
    {
        $this->stringStatement->conditionsSatisfiedBy($this->context);
    }

    /**
     * Benchmark: numeric operators (`gt`, `gte`, `lt`, `lte`).
     *
     * @return void
     */
    #[Bench\BeforeMethods('setUp')]
    #[Bench\Iterations(3)]
    #[Bench\Revs(5000)]
    public function benchNumericOperators(): void
    {
        $this->numericStatement->conditionsSatisfiedBy($this->context);
    }

    /**
     * Benchmark: temporal operators (`before`, `after`, `between`) — the
     * heaviest class because every comparator runs through `strtotime()`.
     *
     * @return void
     */
    #[Bench\BeforeMethods('setUp')]
    #[Bench\Iterations(3)]
    #[Bench\Revs(2000)]
    public function benchTemporalOperators(): void
    {
        $this->temporalStatement->conditionsSatisfiedBy($this->context);
    }

    /**
     * Benchmark: set, boolean, null, IP range and multi-valued operators.
     *
     * @return void
     */
    #[Bench\BeforeMethods('setUp')]
    #[Bench\Iterations(3)]
    #[Bench\Revs(5000)]
    public function benchSetOperators(): void
    {
        $this->setStatement->conditionsSatisfiedBy($this->context);
    }

    /**
     * Benchmark: the full 20-operator chain — matches the budget reference
     * shape so both surfaces measure identical work.
     *
     * @return void
     */
    #[Bench\BeforeMethods('setUp')]
    #[Bench\Iterations(3)]
    #[Bench\Revs(1000)]
    public function benchFullChain(): void
    {
        $this->fullStatement->conditionsSatisfiedBy($this->context);
    }

    /**
     * Build the statement covering string operators.
     *
     * @return \SineMacula\Laravel\Authorization\Evaluation\Statement
     */
    private static function buildStringStatement(): Statement
    {
        return new Statement(
            effect: PolicyEffect::ALLOW,
            actions: ['*'],
            conditions: [
                'eq'          => ['tenant' => 'tenant-99'],
                'neq'         => ['role' => 'guest'],
                'starts_with' => ['path' => '/admin'],
                'ends_with'   => ['file' => '.json'],
                'like'        => ['agent' => 'Mozilla/*'],
            ],
        );
    }

    /**
     * Build the statement covering numeric operators.
     *
     * @return \SineMacula\Laravel\Authorization\Evaluation\Statement
     */
    private static function buildNumericStatement(): Statement
    {
        return new Statement(
            effect: PolicyEffect::ALLOW,
            actions: ['*'],
            conditions: [
                'gt'  => ['age' => 17],
                'gte' => ['quota' => 0],
                'lt'  => ['strikes' => 3],
                'lte' => ['priority' => 10],
            ],
        );
    }

    /**
     * Build the statement covering temporal operators.
     *
     * @return \SineMacula\Laravel\Authorization\Evaluation\Statement
     */
    private static function buildTemporalStatement(): Statement
    {
        return new Statement(
            effect: PolicyEffect::ALLOW,
            actions: ['*'],
            conditions: [
                'before'  => ['scheduled_at' => '2099-01-01T00:00:00Z'],
                'after'   => ['created_at' => '2000-01-01T00:00:00Z'],
                'between' => ['window' => ['2000-01-01T00:00:00Z', '2099-01-01T00:00:00Z']],
            ],
        );
    }

    /**
     * Build the statement covering set, boolean, null, IP range and
     * multi-valued operators.
     *
     * @return \SineMacula\Laravel\Authorization\Evaluation\Statement
     */
    private static function buildSetStatement(): Statement
    {
        return new Statement(
            effect: PolicyEffect::ALLOW,
            actions: ['*'],
            conditions: [
                'in'            => ['country' => ['US', 'GB', 'CA']],
                'not_in'        => ['blocklist' => ['blocked', 'banned']],
                'bool'          => ['verified' => true],
                'null'          => ['deleted_at' => true, 'email' => false],
                'ip_in'         => ['ip' => '10.0.0.0/8'],
                'ip_not_in'     => ['ip' => ['192.168.0.0/16', '2001:db8::/32']],
                'any_value_in'  => ['groups' => ['admins', 'editors']],
                'all_values_in' => ['scopes' => ['posts:read', 'posts:write', 'posts:delete']],
            ],
        );
    }

    /**
     * Build the statement running the full 20-operator chain.
     *
     * @return \SineMacula\Laravel\Authorization\Evaluation\Statement
     */
    private static function buildFullStatement(): Statement
    {
        return new Statement(
            effect: PolicyEffect::ALLOW,
            actions: ['*'],
            conditions: BenchmarkFixtures::conditionChain(),
        );
    }
}
