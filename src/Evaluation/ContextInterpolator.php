<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Arr;

/**
 * Resolve `${namespace.key}` tokens in policy statement strings.
 *
 * Three namespaces are supported:
 *
 * - `${principal.*}`: attributes of the resolved principal. `principal.id` is
 *   the model's key and `principal.type` its morph class (or class name). Other
 *   keys read the model's attribute through `getAttribute()`, or a public
 *   property on a plain object. Hidden attributes (listed in `$hidden`, or left
 *   out of a non-empty `$visible`) and relations are never read.
 * - `${context.*}`: the caller-supplied context array passed to `can()` or
 *   `evaluate()`, as a dot-notation path (e.g. `${context.request.ip}`).
 * - `${resource.*}`: derived from the resource string. `resource.type` is the
 *   segment before the first `:` (the whole string when there is none) and
 *   `resource.id` the segment after it (unresolved when there is none).
 *
 * A token that cannot be resolved to a scalar makes the whole string
 * unresolved: `interpolate()` and `interpolatePattern()` return null, and the
 * statement treats the test as undecidable (a deny applies, an allow does not),
 * never as an empty string. The escape sequence `\${` stands for a literal
 * `${`; any other `${` that does not open a well-formed token (letters, digits,
 * `_` and `.`, starting with a letter or `_`) is malformed and also makes the
 * string unresolved. Every substituted value is a string: numbers are cast and
 * booleans become `true` or `false`.
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
     * @param  object|null  $principal
     * @param  string|null  $resource
     * @param  array<string, mixed>  $context
     * @return string|null
     */
    public function interpolate(string $subject, ?object $principal, ?string $resource, array $context): ?string
    {
        return $this->render($subject, $principal, $resource, $context, false);
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
     * @param  object|null  $principal
     * @param  string|null  $resource
     * @param  array<string, mixed>  $context
     * @return string|null
     */
    public function interpolatePattern(string $pattern, ?object $principal, ?string $resource, array $context): ?string
    {
        return $this->render($pattern, $principal, $resource, $context, true);
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
        foreach (self::split($subject) as $part) {
            if (\preg_match(self::TOKEN_PATTERN, $part) === 1) {
                return true;
            }
        }

        return false;
    }

    /**
     * Determine whether the string contains a `${` that is neither escaped nor
     * the start of a well-formed reference, such as `${context.tenant-id}`.
     *
     * @param  string  $subject
     * @return bool
     */
    public static function hasMalformedReference(string $subject): bool
    {
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
     * @param  object|null  $principal
     * @param  string|null  $resource
     * @param  array<string, mixed>  $context
     * @param  bool  $asPattern
     * @return string|null
     */
    private function render(string $subject, ?object $principal, ?string $resource, array $context, bool $asPattern): ?string
    {
        $rendered = '';

        foreach (self::split($subject) as $part) {
            $piece = $this->renderPart($part, $principal, $resource, $context, $asPattern);

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
     * @param  object|null  $principal
     * @param  string|null  $resource
     * @param  array<string, mixed>  $context
     * @param  bool  $asPattern
     * @return string|null
     */
    private function renderPart(string $part, ?object $principal, ?string $resource, array $context, bool $asPattern): ?string
    {
        if ($part === '\${' || self::isMalformed($part)) {
            return $part === '\${' ? '${' : null;
        }

        if (\preg_match(self::TOKEN_PATTERN, $part) !== 1) {
            return $asPattern ? self::literalPattern($part) : $part;
        }

        $value = $this->resolveToken(\substr($part, 2, -1), $principal, $resource, $context);

        return $asPattern && $value !== null ? \addcslashes($value, self::GLOB_SPECIAL) : $value;
    }

    /**
     * Resolve a single dotted token to its string value, or null when it cannot
     * be resolved.
     *
     * @param  string  $token
     * @param  object|null  $principal
     * @param  string|null  $resource
     * @param  array<string, mixed>  $context
     * @return string|null
     */
    private function resolveToken(string $token, ?object $principal, ?string $resource, array $context): ?string
    {
        $dotPos    = \strpos($token, '.');
        $namespace = $dotPos === false ? $token : \substr($token, 0, $dotPos);
        $key       = $dotPos === false ? '' : \substr($token, $dotPos + 1);

        $value = match ($namespace) {
            'principal' => $this->resolvePrincipal($principal, $key),
            'context'   => $this->resolveContext($context, $key),
            'resource'  => $this->resolveResource($resource, $key),
            default     => null,
        };

        if ($value === null) {
            self::logUnresolved($token);

            return null;
        }

        return \is_bool($value) ? \var_export($value, true) : (string) $value;
    }

    /**
     * Resolve a key from the principal object.
     *
     * @param  object|null  $principal
     * @param  string  $key
     * @return scalar|null
     */
    private function resolvePrincipal(?object $principal, string $key): bool|float|int|string|null
    {
        if ($principal === null || $key === '') {
            return null;
        }

        if ($key === 'type') {
            return $this->resolvePrincipalType($principal);
        }

        /** @var mixed $value */
        $value = $principal instanceof Model
            ? $this->resolveModelAttribute($principal, $key)
            : $this->resolvePublicProperty($principal, $key);

        return \is_scalar($value) ? $value : null;
    }

    /**
     * Read an attribute of an Eloquent principal, refusing hidden attributes
     * and relations.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $principal
     * @param  string  $key
     * @return mixed
     */
    private function resolveModelAttribute(Model $principal, string $key): mixed
    {
        if ($key === 'id') {
            return $principal->getKey();
        }

        $visible = $principal->getVisible();

        if (\in_array($key, $principal->getHidden(), true) || ($visible !== [] && !\in_array($key, $visible, true)) || $principal->isRelation($key)) {
            return null;
        }

        return $principal->getAttribute($key);
    }

    /**
     * Read a public property of a plain principal object.
     *
     * @param  object  $principal
     * @param  string  $key
     * @return mixed
     */
    private function resolvePublicProperty(object $principal, string $key): mixed
    {
        /** @var array<string, mixed> $vars */
        $vars = \get_object_vars($principal);

        return $vars[$key] ?? null;
    }

    /**
     * Resolve the principal type string.
     *
     * Eloquent models with a `getMorphClass` method return their morph alias;
     * all other objects fall back to their fully-qualified class name.
     *
     * @param  object  $principal
     * @return string
     */
    private function resolvePrincipalType(object $principal): string
    {
        if (\method_exists($principal, 'getMorphClass')) {
            return $principal->getMorphClass();
        }

        return $principal::class;
    }

    /**
     * Resolve a dot-notation key from the context array.
     *
     * @param  array<string, mixed>  $context
     * @param  string  $key
     * @return scalar|null
     */
    private function resolveContext(array $context, string $key): bool|float|int|string|null
    {
        if ($key === '') {
            return null;
        }

        /** @var mixed $value */
        $value = Arr::get($context, $key);

        return \is_scalar($value) ? $value : null;
    }

    /**
     * Resolve a key from the resource string representation.
     *
     * `resource.type` returns the segment before the first `:`, or the whole
     * string when there is none. `resource.id` returns the segment after it,
     * and is unresolved when there is none.
     *
     * @param  string|null  $resource
     * @param  string  $key
     * @return string|null
     */
    private function resolveResource(?string $resource, string $key): ?string
    {
        if ($resource === null || $key === '') {
            return null;
        }

        $colonPos = \strpos($resource, ':');

        return match ($key) {
            'id'    => $colonPos === false ? null : \substr($resource, $colonPos + 1),
            'type'  => $colonPos === false ? $resource : \substr($resource, 0, $colonPos),
            default => null,
        };
    }

    /**
     * Log a debug message for an unresolved interpolation token.
     *
     * @param  string  $token
     * @return void
     */
    private static function logUnresolved(string $token): void
    {
        // @codeCoverageIgnoreStart
        // Defensive: Laravel's `logger()` helper is always loaded under a
        // booted framework, so this is reachable only outside one.
        if (!\function_exists('logger')) {
            return;
        }

        // @codeCoverageIgnoreEnd
        try {
            // @phpstan-ignore-next-line function.notFound
            logger()->debug("Unresolved interpolation token '\${{$token}}': the test is undecidable.");
        } catch (\Throwable) { // @phpstan-ignore catch.neverThrown
            // Intentional: mirrors ConditionEvaluator's logging guard.
        }
    }
}
