<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use PHPUnit\Runner\CodeCoverage;

/**
 * Compares a measured wall-clock time with its budget, except while code
 * coverage is being collected.
 *
 * A coverage driver slows every line it records several times over, and more on
 * a shared runner, so a timing budget under coverage measures the driver rather
 * than the code. While PHPUnit collects coverage, under `phpunit` or a
 * `paratest` worker alike, the comparison is counted as an assertion and
 * skipped; the test's other assertions still run. Everywhere else the budget is
 * enforced, as it is when the Performance suite runs on its own, serially and
 * without coverage. Query, row and memory budgets do not depend on the clock
 * and are always enforced.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-require-extends \PHPUnit\Framework\TestCase
 */
trait MeasuresTime
{
    /**
     * Assert that the elapsed seconds stay under the budget, unless code
     * coverage is being collected.
     *
     * @param  float  $budget
     * @param  float  $elapsed
     * @param  string  $message
     * @return void
     */
    protected function assertWithinBudget(float $budget, float $elapsed, string $message): void
    {
        if (CodeCoverage::instance()->isActive()) {
            $this->addToAssertionCount(1);

            return;
        }

        self::assertLessThan($budget, $elapsed, $message);
    }
}
