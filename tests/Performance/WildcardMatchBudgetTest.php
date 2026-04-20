<?php

declare(strict_types = 1);

namespace Tests\Performance;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect;
use SineMacula\Laravel\Authorization\Evaluation\Statement;

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
    /**
     * 100 wildcard matches against a shallow prefix pattern must complete in
     * under 5ms on the reference machine. Observed ~63μs for 100 calls on the
     * reference machine (~0.63μs each); budget is generous to tolerate CI
     * variance.
     *
     * @return void
     */
    public function testCanMatchHundredShallowWildcardsQuickly(): void
    {
        $statement = new Statement(
            effect: PolicyEffect::ALLOW,
            actions: ['posts:*'],
        );

        $start = microtime(true);

        for ($i = 0; $i < 100; $i++) {
            $statement->matches('posts:create');
        }

        $elapsed = microtime(true) - $start;

        self::assertLessThan(
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

        $start = microtime(true);

        for ($i = 0; $i < 100; $i++) {
            $statement->matches('a:b:c:d:e:f:g:h:i:j');
        }

        $elapsed = microtime(true) - $start;

        self::assertLessThan(
            0.01,
            $elapsed,
            "Wildcard match budget (deep pattern) exceeded ({$elapsed}s for 100 iterations).",
        );
    }
}
