<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Resolvers;

use Illuminate\Contracts\Database\Query\Builder;
use SineMacula\Laravel\Authorization\Cache\Resolution;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Cache\ResolutionPins;
use SineMacula\Laravel\Authorization\Database\GrantApplications;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceReference;

/**
 * Resolves the resource policies a check on a resource reads (AUTHZ-7.3).
 *
 * A check on a record reads the policies attached to the record and to its
 * type; a check on a type alone, those attached to the type; a check on an
 * opaque identifier, or on no resource, none. Only the attachments that hold in
 * the tenant and application the check is decided in count: platform-wide ones,
 * those of the tenant, and those of a tenant above it that reach the tenants
 * below, each for every application or the check's own.
 *
 * The attachments and their documents are read in one query, on the write
 * connection, through the resolution cache, as a grantee's policies are: kept
 * for the request or job, and in the persistent store when one is configured. A
 * policy attached to the record and to its type is read once, as the record's.
 * The authorization manager reads through the instance the service provider
 * gives it; a manager given none reads no resource policies. A document that
 * cannot be read is written to the log channel and its exception thrown, so it
 * denies every check on the resource rather than being skipped.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ResourcePolicyResolver
{
    /** @var string The column the query reads the attached resource's key into. */
    private const string RESOURCE_ID = 'attached_resource_id';

    /**
     * Return the policies attached to the resource and to its type, each as a
     * resource policy attached to what it is attached to.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference|null  $resource
     * @return list<\SineMacula\Laravel\Authorization\Evaluation\Policy>
     *
     * @throws \SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException
     */
    public function policiesFor(?ResourceReference $resource): array
    {
        $type = $resource?->type;
        $id   = $resource?->id;

        // A type or key longer than the table stores has no attachments.
        if ($type === null || \strlen($type) > Reference::MAX_BYTES || \strlen((string) $id) > Reference::MAX_BYTES) {
            return [];
        }

        $resolve = static fn (ResolutionPins $pins): Resolution => self::resolve($type, $id, $pins);

        return ResolutionCache::instance()?->rememberResourcePolicies(new Reference($type, $id ?? '*'), $resolve) ?? $resolve(new ResolutionPins)->value;
    }

    /**
     * Resolve the policies attached to the record of the type with the key, and
     * to the type, or to the type alone when there is no key, having pinned the
     * versions the type's attachments and every policy share.
     *
     * @param  string  $type
     * @param  string|null  $id
     * @param  \SineMacula\Laravel\Authorization\Cache\ResolutionPins  $pins
     * @return \SineMacula\Laravel\Authorization\Cache\Resolution<\SineMacula\Laravel\Authorization\Evaluation\Policy>
     *
     * @throws \SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException
     */
    public static function resolve(string $type, ?string $id, ResolutionPins $pins): Resolution
    {
        $pins->resourcePolicies($type);

        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Policy> $class */
        $class = config('authorization.models.policy', Policy::class);

        /** @var string $table */
        $table = config('authorization.tables.resource_policies', 'resource_policies');

        $model = new $class;
        $query = $class::query()->withoutGlobalScopes()->useWritePdo()
            ->join($table, $table . '.policy_id', '=', $model->getQualifiedKeyName())
            ->where($table . '.resource_type', $type)
            ->where(static function (Builder $query) use ($table, $id): void {
                $query->whereNull($table . '.resource_id');

                if ($id === null) {
                    return;
                }

                $query->orWhere($table . '.resource_id', $id);
            })
            ->where(static function (Builder $query) use ($table): void {
                TenantScope::currentChain()->grants($query, $table);
                GrantApplications::only($query, $table, TenantScope::currentApplication());
            })
            ->select([$model->qualifyColumn('*'), $table . '.resource_id as ' . self::RESOURCE_ID]);

        return new Resolution(self::hydrated($query->get()->all(), $type));
    }

    /**
     * Hydrate each policy read once, as attached to the record when it is
     * attached to the record, else to the type.
     *
     * @param  array<int, \SineMacula\Laravel\Authorization\Models\Policy>  $rows
     * @param  string  $type
     * @return list<\SineMacula\Laravel\Authorization\Evaluation\Policy>
     *
     * @throws \SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException
     */
    private static function hydrated(array $rows, string $type): array
    {
        /** @var array<string, array{\SineMacula\Laravel\Authorization\Models\Policy, string}> $attached */
        $attached = [];

        foreach ($rows as $row) {
            $key      = (string) $row->getKey(); // @phpstan-ignore cast.string
            $recordId = $row->getAttribute(self::RESOURCE_ID);
            $resource = \is_scalar($recordId) ? "{$type}:{$recordId}" : "{$type}:*";

            // The record's attachment wins over the type's.
            if (isset($attached[$key]) && $resource === "{$type}:*") {
                continue;
            }

            $attached[$key] = [$row, $resource];
        }

        $policies = [];

        foreach ($attached as [$row, $resource]) {
            $policies[] = GrantResolver::hydrate($row)->withResource($resource);
        }

        return $policies;
    }
}
