<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

/**
 * Compare class names as PHP does: one class has one name whatever its case,
 * with or without a leading backslash.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ClassName
{
    /**
     * Return the class name with no leading backslash, in lower case, so two
     * names of one class compare equal.
     *
     * @param  string  $class
     * @return string
     */
    public static function normalise(string $class): string
    {
        return \strtolower(\ltrim($class, '\\'));
    }

    /**
     * Determine whether the two names name the same class.
     *
     * @param  string  $class
     * @param  string  $other
     * @return bool
     */
    public static function areSame(string $class, string $other): bool
    {
        return self::normalise($class) === self::normalise($other);
    }
}
