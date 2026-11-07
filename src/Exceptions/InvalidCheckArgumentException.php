<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

/**
 * Thrown when a route middleware or a Blade directive of the package is given
 * an argument it cannot honour: a guard that is not an authentication guard, a
 * guard that is also the name of a role, a guard on a check the full decision
 * makes, more arguments than it takes, or, for a middleware, no name to check;
 * when the manager's `any()` or `all()` is given no action to decide; and when
 * its `checkMany()` is given something other than a `CheckInput` to decide.
 *
 * The arguments come from the application's routes, views and code, so this is
 * a programming error rather than a denial, and Laravel renders it as a 500.
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
     * Refuse a guard that is also the name of a role, which may be a second
     * role listed after a comma rather than a guard.
     *
     * @param  string  $guard
     * @return self
     */
    public static function ambiguousGuard(string $guard): self
    {
        return new self(
            "'{$guard}' is both an authentication guard and a role. Separate several roles with '|', or write the guard as"
                . " 'guard={$guard}'.",
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

    /**
     * Refuse a Blade directive given more arguments than it takes.
     *
     * @param  string  $directive
     * @param  int  $count
     * @return self
     */
    public static function tooManyDirectiveArguments(string $directive, int $count): self
    {
        return new self(
            "@{$directive} takes at most two arguments, {$count} given. Separate several names with '|', not ','.",
        );
    }

    /**
     * Refuse a middleware whose list names nothing to check.
     *
     * @param  string  $middleware
     * @return self
     */
    public static function noNames(string $middleware): self
    {
        return new self("{$middleware} names nothing to check. List one or more names, separated by '|'.");
    }

    /**
     * Refuse a check over several actions given none, which neither allows nor
     * refuses anything.
     *
     * @param  string  $method
     * @return self
     */
    public static function noActions(string $method): self
    {
        return new self("{$method}() takes at least one action to decide, none given.");
    }

    /**
     * Refuse a bulk check given something other than a check to decide.
     *
     * @param  int|string  $key
     * @return self
     */
    public static function notACheck(int|string $key): self
    {
        return new self("checkMany() takes a CheckInput for each check to decide; the check at key '{$key}' is not one.");
    }
}
