<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Concerns;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use SineMacula\Laravel\Authorization\Database\UtcDateTime;
use SineMacula\Laravel\Authorization\Services\GrantService;

/**
 * Shared helpers used by the authorizable-identity traits: the ones that feed
 * the resolution-cache TTL-bound and role-tag invalidation paths, and the
 * accessor for the grant service their write methods go through.
 *
 * Extracted into a single trait so `HasAuthorization` (which composes
 * `HasRoles`, `HasPermissions`, and `HasPolicies`) does not trigger a
 * trait-method collision — PHP rejects duplicate method names across composed
 * traits even when the bodies are byte-identical.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-require-extends \Illuminate\Database\Eloquent\Model
 */
trait ResolvesPivotExpiry // @phpstan-ignore trait.unused
{
    /**
     * Gather the primary keys of the supplied models — feeds the role-tag list
     * for tag-capable cache invalidation. Keys that are neither string nor int
     * are silently skipped so a malformed model cannot corrupt the tag set.
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

            if (!\is_string($key) && !\is_int($key)) {
                continue;
            }

            $stringKey = (string) $key;

            if ($stringKey === '') {
                continue;
            }

            $ids[] = $stringKey;
        }

        return \array_values(\array_unique($ids));
    }

    /**
     * Compute the seconds-until-nearest-expiry across the supplied relation's
     * pivot rows. Returns null when no row carries an expiry (or when every
     * expiry is already in the past), which tells the cache to honour its
     * configured TTL verbatim. A concrete positive integer asks the cache to
     * bound the entry lifetime by that window so it invalidates itself in step
     * with the DB-level filter.
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

            if ($smallest !== null && $seconds >= $smallest) {
                continue;
            }

            $smallest = $seconds;
        }

        return $smallest;
    }

    /**
     * Return the seconds until a single pivot row expires, or null when the row
     * has no expiry or it is already in the past. Extracted to keep the
     * scanning loop flat.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  int  $nowTimestamp
     * @return int|null
     */
    private static function authorizationSecondsUntilPivotExpiry(Model $model, int $nowTimestamp): ?int
    {
        // Pivots on relation-bound models arrive as either a concrete `Pivot`
        // instance or, in mutation-kill fixtures, a plain `stdClass` with a
        // scalar `expires_at`. The tests in `MutationKillersTest` intentionally
        // pass non-Model pivots to exercise the scalar-expires_at path, so the
        // access is kept as direct property read with a null-coalesce rather
        // than `getAttribute()` (which requires an Eloquent model). PHPStan
        // cannot see the dynamically-assigned `pivot` relation attribute on
        // `Model` and flags it as missing.
        /** @phpstan-ignore-next-line property.notFound */
        $pivot = $model->pivot ?? null;

        if ($pivot === null) {
            return null;
        }

        /** @var mixed $raw */
        $raw = $pivot->expires_at ?? null;

        $expiresAt = UtcDateTime::toUtc($raw);

        if ($expiresAt === null) {
            return null;
        }

        $seconds = $expiresAt->getTimestamp() - $nowTimestamp;

        return $seconds > 0 ? $seconds : null;
    }

    /**
     * Return the smaller of two nullable seconds-until-expiry values, treating
     * null as "no bound".
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

    /**
     * Return the grant service the identity traits write through, as the
     * container binds it.
     *
     * @return \SineMacula\Laravel\Authorization\Services\GrantService
     *
     * @throws \LogicException
     */
    private static function authorizationGrants(): GrantService
    {
        return GrantService::instance() ?? throw new \LogicException('The authorization grant service is not bound; register the package\'s service provider.');
    }
}
