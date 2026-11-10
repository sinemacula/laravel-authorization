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
 * exposing neither fall back to a per-request `spl_object_hash()`, in which
 * case only the in-memory memo applies.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class PrincipalCacheKey
{
    /** @var list<string> The kinds of entry that hold policy documents, hydrated under the policy limits. */
    private const array POLICY_KINDS = ['policies', 'policies-routed', 'boundaries', 'resource-policies', 'resource-type-policies', 'guardrails'];

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
     * Derive the principal key in `type:id` form.
     *
     * @param  object  $principal
     * @return string
     */
    public static function for(object $principal): string
    {
        return self::type($principal) . ':' . self::id($principal);
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
        if (\method_exists($principal, 'getKey')) {
            /** @var mixed $raw */
            $raw = $principal->getKey();

            if ((\is_string($raw) || \is_int($raw)) && (string) $raw !== '') {
                return (string) $raw;
            }
        }

        return 'obj:' . \spl_object_hash($principal);
    }
}
