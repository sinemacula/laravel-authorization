<?php

declare(strict_types = 1);

namespace Tests\Performance;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\ContextInterpolator;

/**
 * Performance budget for `ContextInterpolator::interpolate()`.
 *
 * The interpolator sits on the statement-matching hot path: every
 * `${...}` token in a resource pattern or condition operand runs the
 * regex callback on every matching statement. A regression in token
 * resolution cost compounds linearly with statement count, so the
 * suite codifies a loose wall-clock budget on a 20-token reference
 * pattern — enough headroom to tolerate normal CI variance while
 * catching a 10× regression.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(ContextInterpolator::class)]
final class ContextInterpolatorBudgetTest extends TestCase
{
    /**
     * Interpolating a 20-token pattern must stay under ~500μs on
     * the reference machine. The PHPBench suite tracks the actual
     * micro-trend (~52μs on the reference machine); this budget is
     * ~10× that so normal CI variance never trips it.
     *
     * @return void
     */
    public function testCanInterpolateTwentyTokenPatternQuickly(): void
    {
        $interpolator = new ContextInterpolator;
        $pattern      = self::buildTwentyTokenPattern();
        $context      = self::buildContext();
        $principal    = new class {
            public string $id   = 'user-42';
            public string $name = 'alice';
        };

        // Run 1,000 iterations — amortises microsecond-level jitter
        // across a measurable window and gives the budget comfortable
        // headroom vs. observed ~52μs per call on the reference
        // machine (≈52ms total).
        $start = \microtime(true);

        for ($i = 0; $i < 1000; $i++) {
            $interpolator->interpolate($pattern, $principal, 'posts:42', $context);
        }

        $elapsed = \microtime(true) - $start;

        self::assertLessThan(
            0.5,
            $elapsed,
            "ContextInterpolator budget exceeded ({$elapsed}s for 1,000 iterations of a 20-token pattern).",
        );
    }

    /**
     * Build a 20-token pattern mixing principal, resource, and
     * dot-notation context lookups — kept here rather than in a
     * shared helper so the performance suite has no runtime
     * dependency on the benchmark-support tree.
     *
     * @return string
     */
    private static function buildTwentyTokenPattern(): string
    {
        $ten = '${principal.id}:${principal.type}:${resource.type}:${resource.id}'
            . ':${context.tenant}:${context.request.ip}:${context.request.method}'
            . ':${context.request.path}:${context.request.country}:${context.environment}';

        return $ten . ':' . $ten;
    }

    /**
     * Build the matching context array — same shape as the bench
     * fixture.
     *
     * @return array<string, mixed>
     */
    private static function buildContext(): array
    {
        return [
            'tenant'  => 'tenant-99',
            'request' => [
                'ip'         => '10.0.0.42',
                'method'     => 'POST',
                'path'       => '/admin/posts/99',
                'country'    => 'US',
                'referrer'   => 'https://example.test/dashboard',
                'user_agent' => 'Mozilla/5.0',
            ],
            'environment' => 'production',
        ];
    }
}
