<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

use Illuminate\Support\Arr;

/**
 * Resolve `${namespace.key}` tokens in policy statement strings.
 *
 * Three namespaces are supported:
 *
 * - `${principal.*}` — attributes of the resolved principal object.
 *   If the principal is an Eloquent model, reads via `getAttribute()`;
 *   otherwise falls back to property access. The pseudo-keys
 *   `principal.id` and `principal.type` resolve to the model key /
 *   class name respectively.
 * - `${context.*}` — the caller-supplied context array passed to `can()` /
 *   `evaluate()`. Supports dot-notation paths (e.g. `${context.request.ip}`).
 * - `${resource.*}` — derived from the resource string. `resource.id` returns
 *   the segment after the first `:`, and `resource.type` returns the segment
 *   before it. If no `:` is present, `resource.id` returns the full string and
 *   `resource.type` returns the full string.
 *
 * Unknown keys resolve to the empty string and emit a debug-level log line. The
 * escape sequence `\${` passes through as a literal `${`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class ContextInterpolator
{
    /** @var string Regex pattern matching `${namespace.key}` tokens; lookbehind rejects the `\${` escape. */
    private const string TOKEN_PATTERN = '/(?<!\\\)\$\{([a-zA-Z_][a-zA-Z0-9_.]*)\}/';

    /**
     * Interpolate all `${...}` tokens in the given pattern string.
     *
     * @param  string  $pattern
     * @param  object|null  $principal
     * @param  string|null  $resource
     * @param  array<string, mixed>  $context
     * @return string
     */
    public function interpolate(string $pattern, ?object $principal, ?string $resource, array $context): string
    {
        $result = \preg_replace_callback(self::TOKEN_PATTERN, fn (array $matches): string => $this->resolveToken($matches[1], $principal, $resource, $context), $pattern);

        // Unescape literal \${ sequences
        return \str_replace('\${', '${', $result ?? $pattern);
    }

    /**
     * Resolve a single dotted token to its string value.
     *
     * @param  string  $token
     * @param  object|null  $principal
     * @param  string|null  $resource
     * @param  array<string, mixed>  $context
     * @return string
     */
    private function resolveToken(string $token, ?object $principal, ?string $resource, array $context): string
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

            return '';
        }

        return (string) $value;
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
        $value = null;

        // Eloquent models: use getAttribute for transparent accessor support
        if (\method_exists($principal, 'getAttribute')) {
            /** @var mixed $value */
            $value = $principal->getAttribute($key);
        } elseif (\property_exists($principal, $key)) {
            // Plain objects: property access
            /** @var array<string, mixed> $vars */
            $vars = \get_object_vars($principal);
            /** @var mixed $value */
            $value = $vars[$key] ?? null;
        }

        return \is_scalar($value) ? $value : null;
    }

    /**
     * Resolve the principal type string.
     *
     * Eloquent models with a `getMorphClass` method return their morph
     * alias; all other objects fall back to their fully-qualified class
     * name.
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
     * `resource.id` returns the segment after the first `:`. `resource.type`
     * returns the segment before the first `:`. If no `:` is present, both
     * return the full string.
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
            'id'    => $colonPos === false ? $resource : \substr($resource, $colonPos + 1),
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
        if (!\function_exists('logger')) {
            return;
        }

        try {
            // @phpstan-ignore-next-line function.notFound
            logger()->debug("Unresolved interpolation token '\${$token}' — resolved to empty string.");
        } catch (\Throwable) {
            // Intentional: mirrors ConditionEvaluator::logUnknownOperator.
        }
    }
}
