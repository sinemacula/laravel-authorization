<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

/**
 * Thrown when a route middleware or a Blade directive of the package is given
 * an argument it cannot honour: a guard that is not an authentication guard, a
 * guard on a check the full decision makes, or more arguments than it takes.
 *
 * The arguments come from the application's routes and views, so this is a
 * programming error rather than a denial, and Laravel renders it as a 500.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class InvalidCheckArgumentException extends \InvalidArgumentException
{
    /**
     * Refuse a guard that is not one of the application's authentication
     * guards.
     *
     * @param  string  $guard
     * @return self
     */
    public static function unknownGuard(string $guard): self
    {
        return new self(
            "'{$guard}' is not an authentication guard. A role check takes the roles, separated by '|', then an optional"
                . ' guard.',
        );
    }

    /**
     * Refuse a guard on a check the full decision makes, which no guard
     * changes.
     *
     * @param  string  $check
     * @param  string  $guard
     * @return self
     */
    public static function unsupportedGuard(string $check, string $guard): self
    {
        return new self(
            "A {$check} check takes no guard: it is decided on the full authorization decision, which no guard"
                . " changes. Remove the guard '{$guard}'.",
        );
    }

    /**
     * Refuse a middleware given more arguments than it takes.
     *
     * @param  string  $middleware
     * @param  int  $count
     * @return self
     */
    public static function tooManyArguments(string $middleware, int $count): self
    {
        return new self(
            "{$middleware} takes at most two arguments, {$count} given. Separate several names with '|', not ','.",
        );
    }
}
