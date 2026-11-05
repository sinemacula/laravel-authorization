<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Concerns;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Carbon;
use SineMacula\Laravel\Authorization\Database\UtcDateTime;
use SineMacula\Laravel\Authorization\Support\GuardScopedLookup;

/**
 * Shared helpers used by the authorizable-identity traits to feed the
 * resolution-cache TTL-bound and role-tag invalidation paths.
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
     * Read the existing pivot row for the authorizable-to-grant triplet `(type,
     * id, $targetId)` through the supplied query on the grant relation's pivot
     * table and return its existence and `expires_at` value. Returns `['exists'
     * => false, 'expires_at' => null]` when no row exists. The query bypasses
     * any relation-level expiry filter so it observes both live and expired
     * pivot rows — both are candidates for an expiry mutation by a re-call to
     * the surface-specific grant method. A relation's pivot query runs on the
     * relation's connection, the one the grant is then written on.
     *
     * The grantee and expiry columns are the grant tables' fixed
     * `authorizable_type`, `authorizable_id` and `expires_at`; the caller names
     * the column that points at the granted row.
     *
     * Shared by the three authorizable-identity traits so the expiry-change
     * detection machinery lives in one place.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $identity
     * @param  \Illuminate\Database\Query\Builder  $pivot
     * @param  string  $targetColumn
     * @param  string  $targetId
     * @return array{exists: bool, expires_at: \DateTimeInterface|null}
     */
    private static function authorizationReadGrantPivot(Model $identity, Builder $pivot, string $targetColumn, string $targetId): array
    {
        $row = $pivot
            ->where('authorizable_type', $identity->getMorphClass())
            ->where('authorizable_id', (string) $identity->getKey())
            ->where($targetColumn, $targetId)
            ->first();

        if ($row === null) {
            return ['exists' => false, 'expires_at' => null];
        }

        return [
            'exists'     => true,
            'expires_at' => UtcDateTime::toUtc($row->expires_at),
        ];
    }

    /**
     * Compare two expiry values for equality. Two nulls are equal (forever vs.
     * forever); a null and a concrete instant differ (forever vs. expiring);
     * two concrete instants are compared by their UTC timestamp so DST and
     * timezone normalisation do not produce spurious false positives. Shared by
     * the three authorizable-identity traits.
     *
     * @param  \DateTimeInterface|null  $left
     * @param  \DateTimeInterface|null  $right
     * @return bool
     */
    private static function areAuthorizationGrantExpiriesEqual(?\DateTimeInterface $left, ?\DateTimeInterface $right): bool
    {
        if ($left === null && $right === null) {
            return true;
        }

        if ($left === null || $right === null) {
            return false;
        }

        return $left->getTimestamp() === $right->getTimestamp();
    }

    /**
     * Return every row of the given class that answers the name under the
     * identity's guard (the package default when the identity names none), in
     * the order the lookup ranks them. Shared by the role and permission
     * traits, which revoke and synchronise by name from these.
     *
     * @param  object  $identity
     * @param  class-string<\Illuminate\Database\Eloquent\Model>  $class
     * @param  string  $name
     * @return list<\Illuminate\Database\Eloquent\Model>
     */
    private static function authorizationAllNamed(object $identity, string $class, string $name): array
    {
        /** @var string $guard */
        $guard = self::authorizationResolveGuard($identity) ?? config('authorization.defaults.guard', 'web');

        return GuardScopedLookup::allForGuard($class, $name, $guard);
    }

    /**
     * Return the models among the given ones the identity holds, read through
     * the grant relation's pivot query on the column that names the granted
     * row, so an expired grant counts as held. Shared by the role and
     * permission traits.
     *
     * @param  \Illuminate\Database\Query\Builder  $pivot
     * @param  string  $column
     * @param  list<\Illuminate\Database\Eloquent\Model>  $models
     * @return list<\Illuminate\Database\Eloquent\Model>
     */
    private static function authorizationHeldAmong(Builder $pivot, string $column, array $models): array
    {
        $keys = \array_map(static fn (Model $model): string => (string) $model->getKey(), $models);
        $held = \array_map(static fn (mixed $key): string => \is_scalar($key) ? (string) $key : '', $pivot->whereIn($column, $keys)->pluck($column)->all());

        return \array_values(\array_filter($models, static fn (Model $model): bool => \in_array((string) $model->getKey(), $held, true)));
    }

    /**
     * Resolve the optional `getAuthorizationGuard()` hook on the identity
     * model. The hook is duck-typed — consumers opt in by declaring the method
     * on their model, so the lookup is routed through reflection to keep
     * PHPStan from narrowing the call on the specific using class (every
     * concrete analysed class either always or never has the method, which
     * would make a direct `method_exists` guard read as a constant condition).
     *
     * @param  object  $identity
     * @return string|null
     */
    private static function authorizationResolveGuard(object $identity): ?string
    {
        $reflection = new \ReflectionObject($identity);

        if (!$reflection->hasMethod('getAuthorizationGuard')) {
            return null;
        }

        $value = $reflection->getMethod('getAuthorizationGuard')->invoke($identity);

        return \is_string($value) ? $value : null;
    }
}
