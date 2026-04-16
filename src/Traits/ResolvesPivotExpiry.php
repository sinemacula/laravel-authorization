<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Traits;

use Illuminate\Support\Carbon;

/**
 * Shared helpers used by the authorizable-identity traits to feed
 * the resolution-cache TTL-bound and role-tag invalidation paths.
 *
 * Extracted into a single trait so `HasAuthorization` (which
 * composes `HasRoles`, `HasPermissions`, and `HasPolicies`) does
 * not trigger a trait-method collision — PHP rejects duplicate
 * method names across composed traits even when the bodies are
 * byte-identical.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
trait ResolvesPivotExpiry // @phpstan-ignore trait.unused
{
    /**
     * Gather the primary keys of the supplied models — feeds the
     * role-tag list for tag-capable cache invalidation. Keys that
     * are neither string nor int are silently skipped so a
     * malformed model cannot corrupt the tag set.
     *
     * @param  iterable<int, \Illuminate\Database\Eloquent\Model>  $models
     * @return array<int, string>
     */
    private static function authorizationCollectModelIds(iterable $models): array
    {
        $ids = [];

        foreach ($models as $model) {
            /** @var mixed $key */
            $key = $model->getKey();

            if (\is_string($key) || \is_int($key)) {
                $stringKey = (string) $key;

                if ($stringKey !== '') {
                    $ids[] = $stringKey;
                }
            }
        }

        return \array_values(\array_unique($ids));
    }

    /**
     * Compute the seconds-until-nearest-expiry across the supplied
     * relation's pivot rows. Returns null when no row carries an
     * expiry (or when every expiry is already in the past), which
     * tells the cache to honour its configured TTL verbatim. A
     * concrete positive integer asks the cache to bound the entry
     * lifetime by that window so it invalidates itself in step
     * with the DB-level filter — closing ISSUES.md #77.
     *
     * @param  iterable<int, \Illuminate\Database\Eloquent\Model>  $related
     * @return int|null
     */
    private static function authorizationNearestPivotExpirySeconds(iterable $related): ?int
    {
        $now      = Carbon::now()->getTimestamp();
        $smallest = null;

        foreach ($related as $model) {
            $seconds = self::authorizationSecondsUntilPivotExpiry($model, $now);

            if ($seconds === null) {
                continue;
            }

            if ($smallest === null || $seconds < $smallest) {
                $smallest = $seconds;
            }
        }

        return $smallest;
    }

    /**
     * Return the seconds until a single pivot row expires, or
     * null when the row has no expiry or it is already in the
     * past. Extracted to keep the scanning loop flat.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  int  $nowTimestamp
     * @return int|null
     */
    private static function authorizationSecondsUntilPivotExpiry(\Illuminate\Database\Eloquent\Model $model, int $nowTimestamp): ?int
    {
        $pivot = $model->pivot ?? null;

        if ($pivot === null) {
            return null;
        }

        /** @var mixed $raw */
        $raw = $pivot->expires_at ?? null;

        $expiresAt = self::authorizationCoerceExpiresAt($raw);

        if ($expiresAt === null) {
            return null;
        }

        $seconds = $expiresAt->getTimestamp() - $nowTimestamp;

        return $seconds > 0 ? $seconds : null;
    }

    /**
     * Coerce a raw pivot `expires_at` value (string, Carbon,
     * `DateTimeInterface`, or null) into a `Carbon` instance or
     * null.
     *
     * @param  mixed  $raw
     * @return \Illuminate\Support\Carbon|null
     */
    private static function authorizationCoerceExpiresAt(mixed $raw): ?Carbon
    {
        if ($raw === null) {
            return null;
        }

        if ($raw instanceof \DateTimeInterface) {
            return Carbon::instance(Carbon::parse($raw));
        }

        if (\is_string($raw) && $raw !== '') {
            return Carbon::parse($raw);
        }

        return null;
    }

    /**
     * Return the smaller of two nullable seconds-until-expiry
     * values, treating null as "no bound".
     *
     * @param  int|null  $left
     * @param  int|null  $right
     * @return int|null
     */
    private static function authorizationMinNullable(?int $left, ?int $right): ?int
    {
        if ($left === null) {
            return $right;
        }

        if ($right === null) {
            return $left;
        }

        return \min($left, $right);
    }
}
