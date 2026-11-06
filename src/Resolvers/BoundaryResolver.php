<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Resolvers;

use Illuminate\Contracts\Database\Query\Builder;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Cache\Resolution;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Cache\ResolutionPins;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableIdentity;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Resolves the permission boundaries of a grantee that apply to a check
 * (AUTHZ-7.4).
 *
 * A grantee has at most one boundary per scope, and every boundary whose scope
 * covers the tenant the check is decided in applies: the platform-wide one, the
 * tenant's own, and an ancestor's that reaches the tenants below it, as a grant
 * reaches down (AUTHZ-5.3). A tenant's boundary never replaces the platform's:
 * every one that applies is intersected at the boundary stage, so a check
 * passes only what each of them allows. With no tenant, only the platform-wide
 * one applies (AUTHZ-5.7).
 *
 * Only an authorizable identity that is a saved model has boundaries, so a
 * subject of any other kind costs no query. The boundaries and their documents
 * are read in one query, on the write connection, through the resolution cache,
 * as a grantee's policies are: kept for the request or job, and in the
 * persistent store when one is configured, so a warm check reads none. A policy
 * set as a boundary in more than one scope is read once. A document that cannot
 * be read is written to the log channel and its exception thrown, so it denies
 * every check for the grantee rather than lifting the cap.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class BoundaryResolver
{
    /**
     * Return the boundaries of the grantee that apply in the tenant the check
     * is decided in, each hydrated for evaluation; none for a grantee that is
     * not a saved authorizable identity.
     *
     * @param  object|null  $grantee
     * @return list<\SineMacula\Laravel\Authorization\Evaluation\Policy>
     *
     * @throws \SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException
     */
    public static function boundariesFor(?object $grantee): array
    {
        if (!$grantee instanceof AuthorizableIdentity || !$grantee instanceof Model || !$grantee->exists) {
            return [];
        }

        $reference = Reference::of($grantee);
        $resolve   = static fn (ResolutionPins $pins): Resolution => self::resolve($reference, $pins);

        return ResolutionCache::instance()?->rememberBoundaries($grantee, $resolve) ?? $resolve(new ResolutionPins)->value;
    }

    /**
     * Resolve the grantee's boundaries that hold in the current tenant, having
     * pinned the version every boundary entry shares.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  \SineMacula\Laravel\Authorization\Cache\ResolutionPins  $pins
     * @return \SineMacula\Laravel\Authorization\Cache\Resolution<\SineMacula\Laravel\Authorization\Evaluation\Policy>
     *
     * @throws \SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException
     */
    public static function resolve(Reference $grantee, ResolutionPins $pins): Resolution
    {
        $pins->boundaries();

        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Policy> $class */
        $class = config('authorization.models.policy', Policy::class);

        /** @var string $table */
        $table = config('authorization.tables.authorizable_boundaries', 'authorizable_boundaries');

        $model = new $class;
        $rows  = $class::query()->withoutGlobalScopes()->useWritePdo()
            ->join($table, $table . '.policy_id', '=', $model->getQualifiedKeyName())
            ->where($table . '.authorizable_type', $grantee->type)
            ->where($table . '.authorizable_id', $grantee->id)
            ->where(static function (Builder $query) use ($table): void {
                TenantScope::currentChain()->grants($query, $table);
            })
            ->select($model->qualifyColumn('*'))
            ->get()
            ->getDictionary();

        $boundaries = [];

        foreach ($rows as $row) {
            $boundaries[] = GrantResolver::hydrate($row);
        }

        return new Resolution($boundaries);
    }
}
