<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Query;

/**
 * Tells which records of a type a resolved resource pattern matches, as
 * `Statement::covers()` matches it against each record's identifier, `T:` and
 * the record's key, so the scope can compare the key in SQL exactly as
 * `fnmatch()` would.
 *
 * A pattern is read as `fnmatch()` reads it, with no flags: `\x` is the
 * character x, `*` any run of characters. A literal names one identifier: the
 * record whose key is the rest of it, when it starts with `T:`, else none. A
 * literal and then one `*` names every record when the literal is a prefix of
 * `T:`, none when the two are disjoint, and otherwise every record whose key
 * starts with the rest of the literal, byte for byte.
 *
 * `covers()` also needs the identifier less its last byte to match when the
 * identifier ends in `:*`, which a key `*`, or one ending in `:*`, makes it do;
 * that is decided on the whole identifier. A literal then never names such a
 * record (it would have to match two identifiers), so a literal whose key is
 * `*` or ends in `:*`, the escaped `T:\*` included, names none; and a prefix
 * that is itself such a key leaves the key exactly the prefix out. A pattern
 * naming every record names every such record too.
 *
 * Every other pattern is refused (null): a `*` anywhere but at the end, more
 * than one, a `?`, a `[`, a trailing lone `\`, or a pattern of `PHP_MAXPATHLEN`
 * bytes or more, which `fnmatch()` refuses.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ResourcePatterns
{
    /**
     * Return which records of the type the resolved pattern matches, or null
     * when the scope cannot compare it with a key.
     *
     * @param  string  $pattern
     * @param  string  $type
     * @return \SineMacula\Laravel\Authorization\Query\KeyTarget|null
     */
    public static function targetOf(string $pattern, string $type): ?KeyTarget
    {
        $decoded = \strlen($pattern) < \PHP_MAXPATHLEN ? self::decode($pattern) : null;

        if ($decoded === null) {
            return null;
        }

        [$literal, $isStarred] = $decoded;

        return $isStarred ? self::starredTarget($literal, $type . ':') : self::literalTarget($literal, $type . ':');
    }

    /**
     * Return which records a literal names: the record whose key is the rest of
     * it after the type's head, unless that key is empty, `*` or ends in `:*`;
     * none for any other literal.
     *
     * @param  string  $literal
     * @param  string  $head
     * @return \SineMacula\Laravel\Authorization\Query\KeyTarget
     */
    private static function literalTarget(string $literal, string $head): KeyTarget
    {
        $key = \str_starts_with($literal, $head) ? \substr($literal, \strlen($head)) : '';

        return $key === '' || self::endsAsType($key) ? KeyTarget::none() : KeyTarget::equals($key);
    }

    /**
     * Return which records a literal and then `*` names: every record when the
     * literal is a prefix of the type's head, none when the two are disjoint,
     * else every record whose key starts with the rest of the literal.
     *
     * @param  string  $literal
     * @param  string  $head
     * @return \SineMacula\Laravel\Authorization\Query\KeyTarget
     */
    private static function starredTarget(string $literal, string $head): KeyTarget
    {
        if (\str_starts_with($head, $literal)) {
            return KeyTarget::all();
        }

        if (!\str_starts_with($literal, $head)) {
            return KeyTarget::none();
        }

        $start = \substr($literal, \strlen($head));

        return KeyTarget::prefix($start, self::endsAsType($start));
    }

    /**
     * Determine whether a key makes its identifier end in `:*`: it is `*`, or
     * ends in `:*`.
     *
     * @param  string  $key
     * @return bool
     */
    private static function endsAsType(string $key): bool
    {
        return $key === '*' || \str_ends_with($key, ':*');
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
