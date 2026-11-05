<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use SineMacula\Laravel\Authorization\Exceptions\InvalidCheckArgumentException;

/**
 * Reads the arguments the package's route middleware and Blade directives are
 * given: the names to check, and the guard that may follow them.
 *
 * Names come as a string or a list of strings, and every entry may hold several
 * names separated by `|`, so `'admin|editor'`, `['admin', 'editor']` and
 * `['admin|editor']` all name the same two roles. Whitespace around a name is
 * trimmed and an empty name is ignored, so an empty argument names nothing and
 * never admits anyone.
 *
 * A guard is never ignored. A role check honours it, so only roles of that
 * guard or of no guard count; a check the full decision makes refuses it, since
 * no guard changes that decision.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class CheckArguments
{
    /**
     * Return the names the argument lists, in order.
     *
     * @param  array<int, string>|string  $value
     * @return list<string>
     */
    public static function names(array|string $value): array
    {
        $names = [];

        foreach ((array) $value as $entry) {
            foreach (\explode('|', $entry) as $name) {
                $name = \trim($name);

                if ($name === '') {
                    continue;
                }

                $names[] = $name;
            }
        }

        return $names;
    }

    /**
     * Return the guard a role check is limited to, or null for none.
     *
     * @param  string|null  $guard
     * @return string|null
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidCheckArgumentException
     */
    public static function guard(?string $guard): ?string
    {
        if ($guard === null) {
            return null;
        }

        $guards = config('auth.guards');

        if (!\is_array($guards) || !\array_key_exists($guard, $guards)) {
            throw InvalidCheckArgumentException::unknownGuard($guard);
        }

        return $guard;
    }

    /**
     * Refuse a guard given to a check the full decision makes.
     *
     * @param  string  $check
     * @param  string|null  $guard
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidCheckArgumentException
     */
    public static function refuseGuard(string $check, ?string $guard): void
    {
        if ($guard !== null) {
            throw InvalidCheckArgumentException::unsupportedGuard($check, $guard);
        }
    }
}
