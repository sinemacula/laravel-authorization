<?php

declare(strict_types = 1);

namespace Benchmarks\Runtime;

use Benchmarks\Support\BenchmarkFixtures;
use PhpBench\Attributes as Bench;
use SineMacula\Laravel\Authorization\Evaluation\Policy;

/**
 * PHPBench micro-benchmark for `Policy::fromArray()`.
 *
 * Tracks the wall-clock cost of hydrating a realistic policy
 * document (20 statements, 5 actions × 3 resources × 2 conditions
 * per statement) into the immutable `Policy` value object. The
 * performance-test suite asserts a hard budget on the same shape —
 * this bench exists for trend tracking across commits.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[Bench\OutputTimeUnit('microseconds')]
final class PolicyParseBench
{
    /** @var array<string, mixed> Policy document array reused across revolutions; populated by `setUp()`. */
    private array $document = [];

    /**
     * Bench setUp — build the reusable policy document once per
     * iteration so parse revolutions measure only parse cost.
     *
     * @return void
     */
    public function setUp(): void
    {
        $this->document = BenchmarkFixtures::policyDocument();
    }

    /**
     * Benchmark: `Policy::fromArray()` on a 20-statement document.
     *
     * @return void
     */
    #[Bench\BeforeMethods('setUp')]
    #[Bench\Iterations(3)]
    #[Bench\Revs(1000)]
    public function benchParse(): void
    {
        Policy::fromArray($this->document);
    }
}
