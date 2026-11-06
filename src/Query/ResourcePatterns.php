<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Query;

/**
 * Tells whether a resolved resource pattern covers every record of a type
 * (N68): `whereAuthorized()` compiles a statement only when every pattern it
 * matches against a record's identifier, `T:` and the record's key, covers
 * every record of the type `T`, whatever the key, so no key is ever compared.
 *
 * A pattern is read as `fnmatch()` reads it, with no flags: `\x` is the
 * character x, `*` any run of characters. It covers every record when it is
 * `*`, `T:*`, or a shorter literal prefix of `T:` and then `*`. Every other
 * pattern is refused, even one that could cover no record of the type, such as
 * another type's: a literal (a record's id), a longer prefix than `T:` before
 * the `*`, a literal and then `*` that is not a prefix of `T:`, a `*` anywhere
 * but at the end, more than one, a `?`, a `[`, or a trailing lone `\`. So is
 * one of `PHP_MAXPATHLEN` bytes or more, which `fnmatch()` refuses.
 *
 * A record whose key ends in `:*` is covered only when the pattern covers its
 * identifier without the `*` too (see `Statement::covers()`); a pattern that
 * covers every record does so for that identifier as well.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ResourcePatterns
{
    /**
     * Determine whether the resolved pattern covers every record of the type,
     * whatever their keys.
     *
     * @param  string  $pattern
     * @param  string  $type
     * @return bool
     */
    public static function coversEveryRecord(string $pattern, string $type): bool
    {
        $decoded = \strlen($pattern) < \PHP_MAXPATHLEN ? self::decode($pattern) : null;

        if ($decoded === null) {
            return false;
        }

        [$literal, $isStarred] = $decoded;

        return $isStarred && \str_starts_with($type . ':', $literal);
    }

    /**
     * Decode a pattern into its literal text and whether a single `*` ends it,
     * or null when it holds any other wildcard, a `*` elsewhere, or a trailing
     * lone `\`.
     *
     * @param  string  $pattern
     * @return array{string, bool}|null
     */
    private static function decode(string $pattern): ?array
    {
        // Escaped characters and plain ones, then at most one star.
        if (\preg_match('/\A((?:\\\.|[^\\\*?\[])*)(\*?)\z/s', $pattern, $parts) !== 1) {
            return null;
        }

        return [(string) \preg_replace('/\\\(.)/s', '$1', $parts[1]), $parts[2] === '*'];
    }
}
