<?php

declare(strict_types = 1);

namespace Tests\Performance;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect;
use SineMacula\Laravel\Authorization\Evaluation\PolicyLimits;
use SineMacula\Laravel\Authorization\Evaluation\Statement;
use Tests\Concerns\MeasuresTime;

/**
 * Performance budget for the `fnmatch`-based wildcard hot path.
 *
 * Every action / permission comparison in the package flows through
 * `fnmatch($pattern, $asked, FNM_NOESCAPE)`. The budget asserts a loose
 * wall-clock bound on 100 repeated matches against a single `posts:*` statement
 * and 100 repeated matches against a 10-segment deep pattern — enough headroom
 * for normal CI variance, tight enough to trip on a 10× regression.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(Statement::class)]
final class WildcardMatchBudgetTest extends TestCase
{
    use MeasuresTime;

    /**
     * 100 wildcard matches against a shallow prefix pattern must complete in
     * under 5ms. Observed ~63μs for 100 calls on the reference machine (~0.63μs
     * each); the budget is generous to tolerate runner variance, and is
     * enforced outside coverage runs.
     *
     * @return void
     */
    public function testCanMatchHundredShallowWildcardsQuickly(): void
    {
        $statement = new Statement(
            effect: PolicyEffect::ALLOW,
            actions: ['posts:*'],
        );

        $start = \microtime(true);

        for ($i = 0; $i < 100; $i++) {
            $statement->matches('posts:create');
        }

        $elapsed = \microtime(true) - $start;

        $this->assertWithinBudget(
            0.005,
            $elapsed,
            "Wildcard match budget (shallow prefix) exceeded ({$elapsed}s for 100 iterations).",
        );
    }

    /**
     * 100 wildcard matches against a 10-segment deep pattern must stay
     * comfortably under the shallow budget — depth does not materially affect
     * `fnmatch` cost on modern libc, and the test guards against a silent
     * regression if the package grows a pre-match transform.
     *
     * @return void
     */
    public function testCanMatchHundredDeepWildcardsQuickly(): void
    {
        $statement = new Statement(
            effect: PolicyEffect::ALLOW,
            actions: ['a:b:c:d:e:f:g:h:i:*'],
        );

        $start = \microtime(true);

        for ($i = 0; $i < 100; $i++) {
            $statement->matches('a:b:c:d:e:f:g:h:i:j');
        }

        $elapsed = \microtime(true) - $start;

        $this->assertWithinBudget(
            0.01,
            $elapsed,
            "Wildcard match budget (deep pattern) exceeded ({$elapsed}s for 100 iterations).",
        );
    }

    /**
     * A many-star action pattern at the length limit, which a delegated admin
     * may write, must not stall a check on a long action it does not match.
     *
     * @return void
     */
    public function testManyStarActionPatternAtTheLimitStaysWithinBudget(): void
    {
        $statement = new Statement(
            effect: PolicyEffect::ALLOW,
            actions: [self::manyStarPattern('')],
        );
        $action = \str_repeat('a', 1000);

        self::assertFalse($statement->matches($action));
        self::assertTrue($statement->matches($action . 'b'));

        $elapsed = $this->fastestOf(3, static function () use ($statement, $action): void {
            for ($i = 0; $i < 100; $i++) {
                $statement->matches($action);
            }
        });

        $this->assertWithinBudget(0.05, $elapsed, "Many-star action pattern budget exceeded ({$elapsed}s for 100 matches).");
    }

    /**
     * A many-star resource pattern at the length limit must not stall a check
     * on the longest record key fnmatch() accepts that it does not match.
     *
     * @return void
     */
    public function testManyStarResourcePatternAtTheLimitStaysWithinBudget(): void
    {
        $statement = new Statement(
            effect: PolicyEffect::ALLOW,
            actions: ['*'],
            resources: [self::manyStarPattern('posts:')],
        );
        $resource = 'posts:' . \str_repeat('a', \PHP_MAXPATHLEN - 7);

        self::assertFalse($statement->matches('posts:read', $resource));
        self::assertTrue($statement->matches('posts:read', \substr($resource, 0, -1) . 'b'));

        $elapsed = $this->fastestOf(3, static function () use ($statement, $resource): void {
            for ($i = 0; $i < 100; $i++) {
                $statement->matches('posts:read', $resource);
            }
        });

        $this->assertWithinBudget(0.05, $elapsed, "Many-star resource pattern budget exceeded ({$elapsed}s for 100 matches).");
    }

    /**
     * Return a pattern of `*a` repeated after the prefix and ending in `b`, as
     * long as the default pattern length limit allows.
     *
     * @param  string  $prefix
     * @return string
     */
    private static function manyStarPattern(string $prefix): string
    {
        $limit = (new PolicyLimits)->patternLength;

        return \str_pad($prefix, $limit - 1, '*a') . 'b';
    }
}
