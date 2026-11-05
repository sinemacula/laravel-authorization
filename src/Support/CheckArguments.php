<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use SineMacula\Laravel\Authorization\Exceptions\InvalidCheckArgumentException;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;

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
 * no guard changes that decision. A role check's guard must be one of the
 * application's authentication guards, and is refused when a role, of any
 * tenant, has the same name: `role:editor,admin` may then mean either role
 * rather than the `admin` guard. Written as `guard=admin`, it is always the
 * guard.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class CheckArguments
{
    /** @var string Prefix that marks a role check's argument as a guard. */
    public const string GUARD_PREFIX = 'guard=';

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
     * The guard may be written bare (`web`) or with the prefix (`guard=web`).
     * Bare, it is refused when a role has the same name, which costs one query.
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

        $explicit = \str_starts_with($guard, self::GUARD_PREFIX);
        $name     = $explicit ? \substr($guard, \strlen(self::GUARD_PREFIX)) : $guard;

        self::refuseUnknownGuard($name);

        if (!$explicit && self::namesARole($name)) {
            throw InvalidCheckArgumentException::ambiguousGuard($name);
        }

        return $name;
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

    /**
     * Refuse a guard that is not one of the application's authentication
     * guards.
     *
     * @param  string  $guard
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidCheckArgumentException
     */
    private static function refuseUnknownGuard(string $guard): void
    {
        $guards = config('auth.guards');

        if (!\is_array($guards) || !\array_key_exists($guard, $guards)) {
            throw InvalidCheckArgumentException::unknownGuard($guard);
        }
    }

    /**
     * Determine whether a role of any tenant has the name.
     *
     * @param  string  $name
     * @return bool
     */
    private static function namesARole(string $name): bool
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Role> $class */
        $class = config('authorization.models.role', Role::class);

        return $class::query()->withoutGlobalScope(TenantScope::class)->where('name', $name)->exists();
    }
}
