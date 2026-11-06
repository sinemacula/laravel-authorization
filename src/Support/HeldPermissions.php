<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

/**
 * Matches an asked action against the names of the permissions a grantee holds,
 * by the wildcard rules (AUTHZ-3.3): a held name is an `fnmatch` pattern
 * against the asked action, compared case-sensitively with backslashes taken
 * literally, so holding `posts:*` covers `posts:create` and holding `*` covers
 * every action, while the asked action is always literal and never widens
 * anything.
 *
 * The match names the held permission that covers the action, the same one
 * whatever order the names were read in (AUTHZ-7.9): the action itself when it
 * is held, else the first covering pattern in byte order. The decision records
 * it as the permission that allowed, and a grantee's `hasPermission()` asks
 * here too, so both read the same rules.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class HeldPermissions
{
    /**
     * Return the held permission that covers the action, or null when none
     * does.
     *
     * @param  array<array-key, string>  $held
     * @param  string  $action
     * @return string|null
     */
    public static function match(array $held, string $action): ?string
    {
        if (\in_array($action, $held, true)) {
            return $action;
        }

        $covering = \array_filter($held, static fn (string $name): bool => \fnmatch($name, $action, \FNM_NOESCAPE));

        \sort($covering, \SORT_STRING);

        return $covering[0] ?? null;
    }
}
