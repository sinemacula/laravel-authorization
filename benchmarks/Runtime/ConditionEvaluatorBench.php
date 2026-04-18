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
 * Conditions are the heaviest per-statement work the evaluator does:
 * every matching statement walks its condition map and dispatches
 * each operator through the `evaluateOperator()` match arm. The
 * bench carves the 18-operator surface into four natural classes
 * so drift in any single arm shows up under its own subject:
 *
 * - string ops     — `eq`, `neq`, `starts_with`, `ends_with`, `string_like`;
 * - numeric ops    — `gt`, `gte`, `lt`, `lte`;
 * - temporal ops   — `before`, `after`, `between`;
 * - set ops        — `in`, `not_in`, `bool`, `null`, `not_null`, `cidr`.
 *
 * A fifth subject runs the full 18-operator chain so the
 * matching budget test has a direct comparator.
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

    /** @var \SineMacula\Laravel\Authorization\Evaluation\Statement Statement covering set / boolean / null / CIDR operators. */
    private Statement $setStatement; // @phpstan-ignore property.uninitialized

    /** @var \SineMacula\Laravel\Authorization\Evaluation\Statement Statement running the full 18-operator chain in one pass. */
    private Statement $fullStatement; // @phpstan-ignore property.uninitialized

    /** @var array<string, mixed> Matching context reused across revolutions. */
    private array $context = [];

    /**
     * Bench setUp — materialise the five statement fixtures once per
     * iteration so revolution cost measures only `evaluateConditions()`.
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
     * Benchmark: string operators (`eq`, `neq`, `starts_with`,
     * `ends_with`, `string_like`).
     *
     * @return void
     */
    #[Bench\BeforeMethods('setUp')]
    #[Bench\Iterations(3)]
    #[Bench\Revs(5000)]
    public function benchStringOperators(): void
    {
        $this->stringStatement->evaluateConditions($this->context);
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
        $this->numericStatement->evaluateConditions($this->context);
    }

    /**
     * Benchmark: temporal operators (`before`, `after`, `between`) —
     * the heaviest class because every comparator runs through
     * `strtotime()`.
     *
     * @return void
     */
    #[Bench\BeforeMethods('setUp')]
    #[Bench\Iterations(3)]
    #[Bench\Revs(2000)]
    public function benchTemporalOperators(): void
    {
        $this->temporalStatement->evaluateConditions($this->context);
    }

    /**
     * Benchmark: set, boolean, null, and CIDR operators.
     *
     * @return void
     */
    #[Bench\BeforeMethods('setUp')]
    #[Bench\Iterations(3)]
    #[Bench\Revs(5000)]
    public function benchSetOperators(): void
    {
        $this->setStatement->evaluateConditions($this->context);
    }

    /**
     * Benchmark: the full 18-operator chain — matches the budget
     * reference shape so both surfaces measure identical work.
     *
     * @return void
     */
    #[Bench\BeforeMethods('setUp')]
    #[Bench\Iterations(3)]
    #[Bench\Revs(1000)]
    public function benchFullChain(): void
    {
        $this->fullStatement->evaluateConditions($this->context);
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
                'tenant' => ['eq' => 'tenant-99'],
                'role'   => ['neq' => 'guest'],
                'path'   => ['starts_with' => '/admin'],
                'file'   => ['ends_with' => '.json'],
                'agent'  => ['string_like' => 'Mozilla/*'],
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
                'age'      => ['gt' => 17],
                'quota'    => ['gte' => 0],
                'strikes'  => ['lt' => 3],
                'priority' => ['lte' => 10],
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
                'scheduled_at' => ['before' => '2099-01-01T00:00:00Z'],
                'created_at'   => ['after' => '2000-01-01T00:00:00Z'],
                'window'       => ['between' => ['2000-01-01T00:00:00Z', '2099-01-01T00:00:00Z']],
            ],
        );
    }

    /**
     * Build the statement covering set, boolean, null, and CIDR operators.
     *
     * @return \SineMacula\Laravel\Authorization\Evaluation\Statement
     */
    private static function buildSetStatement(): Statement
    {
        return new Statement(
            effect: PolicyEffect::ALLOW,
            actions: ['*'],
            conditions: [
                'country'    => ['in' => ['US', 'GB', 'CA']],
                'blocklist'  => ['not_in' => ['blocked', 'banned']],
                'verified'   => ['bool' => true],
                'deleted_at' => ['null' => true],
                'email'      => ['not_null' => true],
                'ip'         => ['cidr' => '10.0.0.0/8'],
            ],
        );
    }

    /**
     * Build the statement running the full 18-operator chain.
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
