<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Resolvers;

use Illuminate\Contracts\Database\Query\Builder;
use SineMacula\Laravel\Authorization\Cache\Resolution;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Cache\ResolutionPins;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\ResourceReference;

/**
 * Resolves the guardrails that apply to a check (AUTHZ-7.6).
 *
 * The guardrails of a check are the platform's and those of the check's tenant
 * and every one of its ancestors in the tenant tree, as a tenant's guardrails
 * reach its subtree (AUTHZ-5.3). The check's tenant is the resource's when the
 * resource has one, also when a platform-wide grant admitted a resource of a
 * tenant outside the scope and the check is decided at platform scope (see
 * `ResourceScope`), so a tenant's guardrails always cap a check on its
 * resources; else it is the tenant the check is decided in. With no tenant,
 * only the platform's apply (AUTHZ-5.7). Every one that applies is intersected
 * at the guardrail stage.
 *
 * The guardrails and their documents are read in one query, on the write
 * connection, through the resolution cache: kept for the request or job, and in
 * the persistent store when one is configured, so a warm check reads none, and
 * a check reads them once however many guardrails apply. A policy set as a
 * guardrail on more than one tenant of the chain is read once. The
 * authorization manager reads through the instance the service provider gives
 * it. A document that cannot be read is written to the log channel and its
 * exception thrown, so it denies every check in its scope rather than lifting
 * the cap.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class GuardrailResolver
{
    /**
     * Return the guardrails that apply to a check on the resource, or on no
     * resource, each hydrated for evaluation.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference|null  $resource
     * @return list<\SineMacula\Laravel\Authorization\Evaluation\Policy>
     *
     * @throws \SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException
     */
    public function guardrailsFor(?ResourceReference $resource): array
    {
        $tenant = $resource?->tenant;

        if ($tenant === null || TenantScope::currentChain()->isAt($tenant)) {
            return self::read();
        }

        // Decided outside the resource's tenant, at platform scope, the
        // guardrails of the resource's tenant and its ancestors still cap it.
        return TenantScope::within($tenant, TenantScope::currentApplication(), static fn (): array => self::read());
    }

    /**
     * Resolve the guardrails that hold in the current scope, having pinned the
     * version every guardrail entry shares.
     *
     * @param  \SineMacula\Laravel\Authorization\Cache\ResolutionPins  $pins
     * @return \SineMacula\Laravel\Authorization\Cache\Resolution<\SineMacula\Laravel\Authorization\Evaluation\Policy>
     *
     * @throws \SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException
     */
    public static function resolve(ResolutionPins $pins): Resolution
    {
        $pins->guardrails();

        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Policy> $class */
        $class = config('authorization.models.policy', Policy::class);

        /** @var string $table */
        $table = config('authorization.tables.guardrails', 'guardrails');

        $model = new $class;
        $rows  = $class::query()->withoutGlobalScopes()->useWritePdo()
            ->join($table, $table . '.policy_id', '=', $model->getQualifiedKeyName())
            ->where(static function (Builder $query) use ($table): void {
                TenantScope::currentChain()->owners($query, $table . '.tenant_type', $table . '.tenant_id');
            })
            ->select($model->qualifyColumn('*'))
            ->get()
            ->getDictionary();

        $guardrails = [];

        foreach ($rows as $row) {
            $guardrails[] = GrantResolver::hydrate($row);
        }

        return new Resolution($guardrails);
    }

    /**
     * Read the guardrails that hold in the current scope, through the
     * resolution cache.
     *
     * @return list<\SineMacula\Laravel\Authorization\Evaluation\Policy>
     *
     * @throws \SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException
     */
    private static function read(): array
    {
        $resolve = static fn (ResolutionPins $pins): Resolution => self::resolve($pins);

        return ResolutionCache::instance()?->rememberGuardrails($resolve) ?? $resolve(new ResolutionPins)->value;
    }
}
