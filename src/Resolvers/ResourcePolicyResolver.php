<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Resolvers;

use Illuminate\Contracts\Database\Query\Builder;
use SineMacula\Laravel\Authorization\Cache\Resolution;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Cache\ResolutionPins;
use SineMacula\Laravel\Authorization\Database\GrantApplications;
use SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Evaluation\Statement;
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
 * below, each for every application or the check's own. A check on a resource
 * of a tenant that is decided outside it, at platform scope once the subject
 * holds the action's permission platform-wide (see `ResourceScope`), also reads
 * the denies attached in the resource's own tenant, so a deny that tenant
 * attached to its resource applies to everyone checking it; that tenant's
 * allows do not apply there.
 *
 * A key the table cannot store (empty, `*`, holding a NUL byte or longer than
 * it stores) has no attachment of its own, so a check on such a record reads
 * its type's alone, never none. A type alone is cached apart from every record.
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
    /** @var string The column of an attachment holding the attached record's key, null for a type's. */
    private const string ATTACHED_KEY = '.resource_id';

    /** @var string The column the query reads the attached resource's key into. */
    private const string RESOURCE_ID = 'attached_resource_id';

    /** @var int How many policies attached to records are read at a time. */
    private const int RECORD_PAGE = 100;

    /**
     * Return the policies attached to the resource and to its type, each as a
     * resource policy attached to what it is attached to, and, for a resource
     * of a tenant the check is decided outside, the denies attached in that
     * tenant too.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference|null  $resource
     * @return list<\SineMacula\Laravel\Authorization\Evaluation\Policy>
     *
     * @throws \SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException
     */
    public function policiesFor(?ResourceReference $resource): array
    {
        // A type longer than the table stores has no attachments.
        if ($resource === null || $resource->type === null || \strlen($resource->type) > Reference::MAX_BYTES) {
            return [];
        }

        // No attachment can name a key the table cannot store, so a record of
        // such a key has only its type's.
        $type     = $resource->type;
        $id       = self::isStorableKey($resource->id) ? $resource->id : null;
        $policies = self::read($type, $id);
        $tenant   = $resource->tenant;

        if ($tenant === null || TenantScope::currentChain()->isAt($tenant)) {
            return $policies;
        }

        // Decided outside the resource's tenant, at platform scope, the
        // resource's own tenant's denies still apply to everyone; its allows
        // stay with the scope the check is decided in.
        $own = TenantScope::within($tenant, TenantScope::currentApplication(), static fn (): array => self::read($type, $id));

        return [...$policies, ...self::deniesOf($own, $policies)];
    }

    /**
     * Determine whether a policy attached to a record of the type, in any
     * tenant and for any application, has a statement naming the action, so
     * `whereAuthorized()` can refuse it: it compiles no attachment to a record
     * (N68). The attached policies are read on the write connection, past the
     * resolution cache, so an attachment made since the last check counts, a
     * page at a time, each parsed once and none after the first that names the
     * action; a type with no record attachments reads one empty page. A type
     * longer than the table stores has none.
     *
     * @param  string  $type
     * @param  string  $action
     * @return bool
     *
     * @throws \SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException
     */
    public function hasRecordPolicyFor(string $type, string $action): bool
    {
        if (\strlen($type) > Reference::MAX_BYTES) {
            return false;
        }

        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Policy> $class */
        $class = config('authorization.models.policy', Policy::class);

        /** @var string $table */
        $table = config('authorization.tables.resource_policies', 'resource_policies');

        $model    = new $class;
        $policies = $class::query()->withoutGlobalScopes()->useWritePdo()
            ->whereIn($model->getQualifiedKeyName(), static function (Builder $query) use ($table, $type): void {
                $query->select($table . '.policy_id')->from($table)->where($table . '.resource_type', $type)->whereNotNull($table . self::ATTACHED_KEY);
            })
            ->lazyById(self::RECORD_PAGE);

        $names = static fn (Statement $statement): bool => $statement->coversAction($action);

        foreach ($policies as $policy) {
            if (\array_filter(GrantResolver::hydrate($policy)->statements, $names) !== []) {
                return true;
            }
        }

        return false;
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
                $query->whereNull($table . self::ATTACHED_KEY);

                if ($id === null) {
                    return;
                }

                $query->orWhere($table . self::ATTACHED_KEY, $id);
            })
            ->where(static function (Builder $query) use ($table): void {
                TenantScope::currentChain()->grants($query, $table);
                GrantApplications::only($query, $table, TenantScope::currentApplication());
            })
            ->select([$model->qualifyColumn('*'), $table . '.resource_id as ' . self::RESOURCE_ID]);

        return new Resolution(self::hydrated($query->get()->all(), $type));
    }

    /**
     * Read the policies attached to the record of the type with the key, and to
     * the type, or to the type alone when there is no key, in the tenant and
     * application the check is decided in, through the resolution cache.
     *
     * @param  string  $type
     * @param  string|null  $id
     * @return list<\SineMacula\Laravel\Authorization\Evaluation\Policy>
     *
     * @throws \SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException
     */
    private static function read(string $type, ?string $id): array
    {
        $resolve = static fn (ResolutionPins $pins): Resolution => self::resolve($type, $id, $pins);

        return ResolutionCache::instance()?->rememberResourcePolicies($type, $id, $resolve) ?? $resolve(new ResolutionPins)->value;
    }

    /**
     * Determine whether a record's key is one an attachment can name: not
     * empty, not `*`, without a NUL byte and within the bytes the table stores.
     *
     * @param  string|null  $id
     * @return bool
     *
     * @phpstan-assert-if-true string $id
     */
    private static function isStorableKey(?string $id): bool
    {
        if ($id === null || \in_array($id, ['', '*'], true)) {
            return false;
        }

        return !\str_contains($id, "\0") && \strlen($id) <= Reference::MAX_BYTES;
    }

    /**
     * Return the deny statements of each policy read that is not among those
     * already read, each policy with its deny statements alone, at the
     * positions they hold in its document.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Evaluation\Policy>  $policies
     * @param  list<\SineMacula\Laravel\Authorization\Evaluation\Policy>  $read
     * @return list<\SineMacula\Laravel\Authorization\Evaluation\Policy>
     */
    private static function deniesOf(array $policies, array $read): array
    {
        $seen = [];

        foreach ($read as $policy) {
            $seen[$policy->id . "\0" . $policy->resource] = true;
        }

        $denies = [];

        foreach ($policies as $policy) {
            $statements = \array_filter($policy->statements, static fn (Statement $statement): bool => $statement->effect === PolicyEffect::DENY);

            if ($statements === [] || isset($seen[$policy->id . "\0" . $policy->resource])) {
                continue;
            }

            $denies[] = new EvaluationPolicy($policy->name, $statements, $policy->version, $policy->id, $policy->resource);
        }

        return $denies;
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
            $key = (string) $row->getKey(); // @phpstan-ignore cast.string

            /** @var string|null $recordId */
            $recordId = $row->getAttribute(self::RESOURCE_ID);

            // The record's attachment wins over the type's, told apart by its
            // key, never by its label.
            if ($recordId === null && isset($attached[$key])) {
                continue;
            }

            $attached[$key] = [$row, $recordId === null ? "{$type}:*" : "{$type}:{$recordId}"];
        }

        $policies = [];

        foreach ($attached as [$row, $resource]) {
            $policies[] = GrantResolver::hydrate($row)->withResource($resource);
        }

        return $policies;
    }
}
