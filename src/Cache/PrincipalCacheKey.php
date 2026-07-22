<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Cache;

/**
 * Derives the principal portion of resolution-cache keys.
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
