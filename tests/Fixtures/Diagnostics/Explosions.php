<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Diagnostics;

/**
 * Count every seam built, or any of its methods called, among the seams that
 * explode, so a test can prove the configuration report builds nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class Explosions
{
    /** @var int How many times a seam that explodes was built or called. */
    public static int $count = 0;

    /**
     * Count the explosion and throw.
     *
     * @return never
     *
     * @throws \LogicException
     */
    public static function explode(): never
    {
        self::$count++;

        throw new \LogicException('A seam the report must not build was built or called.');
    }
}
