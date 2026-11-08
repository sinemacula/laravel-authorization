<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

use SineMacula\Laravel\Authorization\Support\AuthorizationLog;

/**
 * Resolve `${namespace.path}` tokens in policy statement strings.
 *
 * Every token is a dot path of the check's context, read by the same resolver
 * as condition keys: `${subject.id}`, `${resource.owner.id}`, `${request.ip}`,
 * `${input.post}`, `${environment.time}`. The namespace is built the first time
 * the check reads it. A namespace the context does not hold, such as `context`,
 * is unresolved, and `${resource.id}` is unresolved for a check whose resource
 * has no id: it is never read by splitting the resource's identifier.
 *
 * A token that cannot be resolved to a scalar (a missing key, a null, a list or
 * map) makes the whole string unresolved: `interpolate()` and
 * `interpolatePattern()` return null, and the statement treats the test as
 * undecidable (a deny applies, an allow does not), never as an empty string.
 * The escape sequence `\${` stands for a literal `${`; any other `${` that does
 * not open a well-formed token (letters, digits, `_` and `.`, starting with a
 * letter or `_`) is malformed and also makes the string unresolved. Every
 * substituted value is a string: numbers are cast and booleans become `true` or
 * `false`.
 *
 * A reference that cannot be resolved is noted with the check's context, which
 * an explained check records by key (see `CheckContext::noteUnresolved()`).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class ContextInterpolator
{
    /** @var string Regex splitting a string into escapes, tokens and literal text. */
    private const string SPLIT_PATTERN = '/(\\\\\$\{|\$\{[a-zA-Z_][a-zA-Z0-9_.]*\})/';

    /** @var string Regex matching one whole `${namespace.key}` token. */
    private const string TOKEN_PATTERN = '/^\$\{[a-zA-Z_][a-zA-Z0-9_.]*\}$/';

    /** @var string Characters escaped in a value substituted into a glob pattern. */
    private const string GLOB_SPECIAL = '\*?[]';

    /**
     * Interpolate every `${...}` token in a literal string.
     *
     * Returns null when any token cannot be resolved.
     *
     * @param  string  $subject
     * @param  array<array-key, mixed>|\SineMacula\Laravel\Authorization\Evaluation\CheckContext  $context
     * @return string|null
     */
    public function interpolate(string $subject, array|CheckContext $context = []): ?string
    {
        return self::render($subject, CheckContext::from($context), false);
    }

    /**
     * Interpolate every `${...}` token in a glob pattern, returning a pattern
     * for `fnmatch()` without `FNM_NOESCAPE`.
     *
     * The pattern's own text keeps its glob meaning, with backslashes made
     * literal; substituted values are escaped so they only ever match
     * themselves (a value of `*` never widens the pattern). Returns null when
     * any token cannot be resolved.
     *
     * @param  string  $pattern
     * @param  array<array-key, mixed>|\SineMacula\Laravel\Authorization\Evaluation\CheckContext  $context
     * @return string|null
     */
    public function interpolatePattern(string $pattern, array|CheckContext $context = []): ?string
    {
        return self::render($pattern, CheckContext::from($context), true);
    }

    /**
     * Determine whether the string contains at least one well-formed `${…}`
     * reference (an escaped `\${` is not one).
     *
     * @param  string  $subject
     * @return bool
     */
    public static function containsReference(string $subject): bool
    {
        return self::references($subject) !== [];
    }

    /**
     * Return the path of every well-formed `${…}` reference in the string, in
     * order (an escaped `\${` is not one), such as `request.ip` for
     * `${request.ip}`.
     *
     * @param  string  $subject
     * @return list<string>
     */
    public static function references(string $subject): array
    {
        $references = [];

        foreach (self::split($subject) as $part) {
            if (\preg_match(self::TOKEN_PATTERN, $part) === 1) {
                $references[] = \substr($part, 2, -1);
            }
        }

        return $references;
    }

    /**
     * Determine whether the string contains a `${` that is neither escaped nor
     * the start of a well-formed reference, such as `${input.tenant-id}`.
     *
     * @param  string  $subject
     * @return bool
     */
    public static function hasMalformedReference(string $subject): bool
    {
        if (!\str_contains($subject, '${')) {
            return false;
        }

        foreach (self::split($subject) as $part) {
            if (self::isMalformed($part)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Prepare a pattern that is not interpolated for `fnmatch()` without
     * `FNM_NOESCAPE`, so its backslashes stay literal.
     *
     * @param  string  $pattern
     * @return string
     */
    public static function literalPattern(string $pattern): string
    {
        return \str_replace('\\', '\\\\', $pattern);
    }

    /**
     * Render the string, resolving every token.
     *
     * @param  string  $subject
     * @param  \SineMacula\Laravel\Authorization\Evaluation\CheckContext  $context
     * @param  bool  $asPattern
     * @return string|null
     */
    private static function render(string $subject, CheckContext $context, bool $asPattern): ?string
    {
        $rendered = '';

        foreach (self::split($subject) as $part) {
            $piece = self::renderPart($part, $context, $asPattern);

            if ($piece === null) {
                return null;
            }

            $rendered .= $piece;
        }

        return $rendered;
    }

    /**
     * Split a string into escapes, well-formed tokens and literal text.
     *
     * @param  string  $subject
     * @return list<string>
     */
    private static function split(string $subject): array
    {
        $parts = \preg_split(self::SPLIT_PATTERN, $subject, -1, \PREG_SPLIT_DELIM_CAPTURE | \PREG_SPLIT_NO_EMPTY);

        return \is_array($parts) ? $parts : [];
    }

    /**
     * Determine whether a literal-text part of a split string contains a `${`,
     * which can only be a malformed reference since escapes and well-formed
     * tokens are split out.
     *
     * @param  string  $part
     * @return bool
     */
    private static function isMalformed(string $part): bool
    {
        return $part !== '\${' && \preg_match(self::TOKEN_PATTERN, $part) !== 1 && \str_contains($part, '${');
    }

    /**
     * Render one part of a split string: an escaped `${`, a token, or literal
     * text. Returns null for a token that cannot be resolved and for a
     * malformed reference.
     *
     * @param  string  $part
     * @param  \SineMacula\Laravel\Authorization\Evaluation\CheckContext  $context
     * @param  bool  $asPattern
     * @return string|null
     */
    private static function renderPart(string $part, CheckContext $context, bool $asPattern): ?string
    {
        if ($part === '\${' || self::isMalformed($part)) {
            return $part === '\${' ? '${' : null;
        }

        if (\preg_match(self::TOKEN_PATTERN, $part) !== 1) {
            return $asPattern ? self::literalPattern($part) : $part;
        }

        $value = self::resolveToken(\substr($part, 2, -1), $context);

        return $asPattern && $value !== null ? \addcslashes($value, self::GLOB_SPECIAL) : $value;
    }

    /**
     * Resolve a single dotted token to its string value, or null when its key
     * is missing or its value is not a scalar, noting it with the context as
     * unresolved, which an explained check records.
     *
     * @param  string  $token
     * @param  \SineMacula\Laravel\Authorization\Evaluation\CheckContext  $context
     * @return string|null
     */
    private static function resolveToken(string $token, CheckContext $context): ?string
    {
        $value = $context->lookup($token)[1];

        if (!\is_scalar($value)) {
            $context->noteUnresolved($token);
            self::logUnresolved($token);

            return null;
        }

        return \is_bool($value) ? \var_export($value, true) : (string) $value;
    }

    /**
     * Log a debug message for an unresolved interpolation token.
     *
     * @param  string  $token
     * @return void
     */
    private static function logUnresolved(string $token): void
    {
        AuthorizationLog::debug("Unresolved interpolation token '\${{$token}}': the test is undecidable.");
    }
}
