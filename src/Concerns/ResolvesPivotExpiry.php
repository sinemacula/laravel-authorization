<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Concerns;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection as EloquentCollection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphToMany;
use Illuminate\Support\Carbon;
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
     * Build the relation onto one kind of grant: polymorphic on the grantee,
     * through the target's grant table and pivot class, with the expiry and
     * timestamps on the pivot, and without grants that have expired.
     *
     * Shared by the roles, permissions and policies relations so the grant
     * tables are always read the same way.
     *
     * @template TRelated of \Illuminate\Database\Eloquent\Model
     * @template TPivot of \Illuminate\Database\Eloquent\Relations\MorphPivot
     *
     * @param  class-string<TRelated>  $related
     * @param  string  $table
     * @param  string  $relatedKey
     * @param  class-string<TPivot>  $pivotClass
     * @return \Illuminate\Database\Eloquent\Relations\MorphToMany<TRelated, $this, TPivot, 'pivot'>
     */
    private function authorizationGrantRelation(string $related, string $table, string $relatedKey, string $pivotClass): MorphToMany
    {
        // The `where(...)` and inner `whereNull()/orWhere()` calls are resolved
        // by PHPStan to static methods on Eloquent's Builder via Laravel's
        // annotation soup — the underlying dispatch is instance-level. Same
        // pattern, same justification, as `GuardScopedLookup`.
        // @phpstan-ignore staticMethod.dynamicCall
        return $this->morphToMany(
            related: $related,
            name: 'authorizable',
            table: $table,
            foreignPivotKey: 'authorizable_id',
            relatedPivotKey: $relatedKey,
        )
            ->using($pivotClass)
            ->withPivot('expires_at')
            ->withTimestamps()
            ->where(static function (Builder $query) use ($table): void {
                // @phpstan-ignore staticMethod.dynamicCall
                $query->whereNull($table . '.expires_at')
                    ->orWhere($table . '.expires_at', '>', Carbon::now('UTC'));
            });
    }

    /**
     * Return the grants of the given relation, loading them first when they are
     * not loaded yet.
     *
     * Loading is explicit, never lazy, so an identity hydrated from a query of
     * several rows resolves under `Model::preventLazyLoading()` as well.
     *
     * @param  string  $relation
     * @return \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model>
     */
    private function authorizationLoadedGrants(string $relation): EloquentCollection
    {
        $this->loadMissing($relation);

        /** @var \Illuminate\Database\Eloquent\Collection<int, \Illuminate\Database\Eloquent\Model> */
        return $this->getRelation($relation);
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
