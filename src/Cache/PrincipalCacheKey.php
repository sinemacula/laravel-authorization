<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Cache;

use SineMacula\Laravel\Authorization\Evaluation\PolicyLimits;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;

/**
 * Derives the principal portion of resolution-cache keys, and the whole key of
 * a persistent entry.
 *
 * Eloquent models use their canonical `getMorphClass()` + `getKey()` pairing.
 * Non-Eloquent principals are duck-typed on those same accessors; principals
 * with no usable key fall back to a per-request `spl_object_hash()`, in which
 * case only the in-memory memo applies. Each part has its '%' and ':' escaped,
 * so no two principals, nor a principal and the scope after it, share a key.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class PrincipalCacheKey
{
    /** @var list<string> The kinds of entry that hold policy documents, hydrated under the policy limits, an identity's included (see `BreakGlassActivations::kindOf()`). */
    private const array POLICY_KINDS = [
        'policies',
        'policies-routed',
        'boundaries',
        'resource-policies',
        'resource-type-policies',
        'guardrails',
        'identity-policies',
        'identity-policies-routed',
        'identity-boundaries',
    ];

    /**
     * Return the key of the kind's persistent entry for the grantee under the
     * prefix, the tenant the tenant scope applies, and whether it decides just
     * below that tenant, and the subject's application.
     *
     * A policies entry, a grantee's or a resource's, is also keyed by the
     * policy limits it was hydrated under. Its documents were checked against
     * the limits when they were read from the database, and are not checked
     * again when read from the store, so a change to any limit makes every
     * entry built under the old limits miss, and the policies are read again
     * and checked against the new ones. The memo, which lasts one request or
     * job, is keyed without them, so a memo hit costs nothing more.
     *
     * @param  string  $prefix
     * @param  string  $kind
     * @param  object  $grantee
     * @return string
     */
    public static function entry(string $prefix, string $kind, object $grantee): string
    {
        return "{$prefix}:{$kind}:" . self::for($grantee)
            . ':' . TenantScope::scopeKey()
            . (\in_array($kind, self::POLICY_KINDS, true) ? ':limits:' . PolicyLimits::fromConfig()->fingerprint() : '');
    }

    /**
     * Determine whether the principal exposes no usable key, so it is keyed by
     * an object hash that PHP gives another object once it is gone.
     *
     * @param  object  $principal
     * @return bool
     */
    public static function isKeyless(object $principal): bool
    {
        return self::key($principal) === null;
    }

    /**
     * Derive the principal key in `type:id` form.
     *
     * @param  object  $principal
     * @return string
     */
    public static function for(object $principal): string
    {
        return self::escape(self::type($principal)) . ':' . self::id($principal);
    }

    /**
     * Escape '%' and ':' in one part of a key, so the parts can be told apart.
     *
     * @param  string  $value
     * @return string
     */
    public static function escape(string $value): string
    {
        return \strtr($value, ['%' => '%25', ':' => '%3A']);
    }

    /**
     * Derive the type portion of the key, preferring a non-empty morph class
     * over the concrete class name.
     *
     * @param  object  $principal
     * @return string
     */
    private static function type(object $principal): string
    {
        if (!\method_exists($principal, 'getMorphClass')) {
            return $principal::class;
        }

        /** @var mixed $morph */
        $morph = $principal->getMorphClass();

        return \is_string($morph) && $morph !== '' ? $morph : $principal::class;
    }

    /**
     * Derive the identifier portion of the key, falling back to a per-request
     * object hash when the principal exposes no usable key.
     *
     * @param  object  $principal
     * @return string
     */
    private static function id(object $principal): string
    {
        $key = self::key($principal);

        // An escaped key never holds '%o', so none matches this one.
        return $key === null ? '%obj' . \spl_object_hash($principal) : self::escape($key);
    }

    /**
     * Return the principal's key when it is an integer or a non-empty string.
     *
     * @param  object  $principal
     * @return string|null
     */
    private static function key(object $principal): ?string
    {
        /** @var mixed $key */
        $key = \method_exists($principal, 'getKey') ? $principal->getKey() : null;

        return (\is_int($key) || \is_string($key)) && $key !== '' ? (string) $key : null;
    }
}
