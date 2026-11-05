<?php

declare(strict_types = 1);

namespace Tests\Concerns;

/**
 * Catches what a write throws when it is refused, for a test that checks the
 * refusal and then carries on, where the refusal comes from a model observer or
 * pivot hook static analysis cannot follow.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-require-extends \PHPUnit\Framework\TestCase
 */
trait CatchesRefusals
{
    /**
     * Run the write and return what it threw, failing the test when it threw
     * nothing.
     *
     * @param  \Closure(): mixed  $write
     * @return \Throwable
     */
    protected static function refusalOf(\Closure $write): \Throwable
    {
        try {
            $write();
        } catch (\Throwable $exception) {
            return $exception;
        }

        self::fail('The write was not refused.');
    }
}
