<?php

declare(strict_types = 1);

namespace Benchmarks\Runtime;

use Benchmarks\Support\BenchmarkFixtures;
use PhpBench\Attributes as Bench;
use SineMacula\Laravel\Authorization\Evaluation\ContextInterpolator;

/**
 * PHPBench micro-benchmark for `ContextInterpolator::interpolate()`.
 *
 * The interpolator runs once per resource pattern and once per
 * condition operand on every matching statement, so parse-time
 * overhead compounds with statement count. The bench tracks three
 * shapes:
 *
 * - a no-token string (common path — most action patterns are plain);
 * - a 10-token realistic pattern mixing principal / resource / context;
 * - a 20-token wide pattern (budget reference shape).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[Bench\OutputTimeUnit('microseconds')]
final class ContextInterpolatorBench
{
    /** Resource string used by every subject. */
    private const string RESOURCE = 'posts:42';

    /** @var \SineMacula\Laravel\Authorization\Evaluation\ContextInterpolator Reusable interpolator across revolutions. */
    private ContextInterpolator $interpolator; // @phpstan-ignore property.uninitialized

    /** @var string 10-token pattern populated by `setUp()`. */
    private string $pattern10 = '';

    /** @var string 20-token pattern populated by `setUp()`. */
    private string $pattern20 = '';

    /** @var array<string, mixed> Context array populated by `setUp()`. */
    private array $context = [];

    /** @var object Plain principal stand-in with scalar attributes. */
    private object $principal; // @phpstan-ignore property.uninitialized

    /**
     * Bench setUp — prime fixtures reused across every revolution.
     *
     * @return void
     */
    public function setUp(): void
    {
        $this->interpolator = new ContextInterpolator;
        $this->pattern10    = BenchmarkFixtures::interpolationPattern();
        $this->pattern20    = BenchmarkFixtures::interpolationPatternWide();
        $this->context      = BenchmarkFixtures::interpolationContext();

        $this->principal = new class {
            /** @var string */
            public string $id = 'user-42';

            /** @var string */
            public string $name = 'alice';
        };
    }

    /**
     * Benchmark: no-token pattern — baseline regex-miss cost.
     *
     * @return void
     */
    #[Bench\BeforeMethods('setUp')]
    #[Bench\Iterations(3)]
    #[Bench\Revs(5000)]
    public function benchNoTokens(): void
    {
        $this->interpolator->interpolate('plain:resource:string', $this->principal, self::RESOURCE, $this->context);
    }

    /**
     * Benchmark: 10-token realistic pattern.
     *
     * @return void
     */
    #[Bench\BeforeMethods('setUp')]
    #[Bench\Iterations(3)]
    #[Bench\Revs(2000)]
    public function benchTenTokens(): void
    {
        $this->interpolator->interpolate($this->pattern10, $this->principal, self::RESOURCE, $this->context);
    }

    /**
     * Benchmark: 20-token wide pattern — budget reference.
     *
     * @return void
     */
    #[Bench\BeforeMethods('setUp')]
    #[Bench\Iterations(3)]
    #[Bench\Revs(1000)]
    public function benchTwentyTokens(): void
    {
        $this->interpolator->interpolate($this->pattern20, $this->principal, self::RESOURCE, $this->context);
    }
}
