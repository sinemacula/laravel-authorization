<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Resolvers;

use Illuminate\Container\Container;
use Illuminate\Contracts\Database\Query\Builder;
use SineMacula\Laravel\Authorization\Cache\Resolution;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Cache\ResolutionPins;
use SineMacula\Laravel\Authorization\Database\GrantApplications;
use SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect;
use SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Evaluation\Statement;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Query\Dialects\Dialects;
use SineMacula\Laravel\Authorization\Query\SchemaInspector;
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
 * `policiesForMany()` reads those of many resources at once, one query for the
 * records of each type, and keeps each record's entry, so a check on any one of
 * them then reads none; when the table compares keys otherwise than byte for
 * byte, folding case say, each record's are read on their own instead. The
 * authorization manager reads through the instance the service provider gives
 * it; a manager given none reads no resource policies. A document that cannot
 * be read is written to the log channel and its exception thrown, so it denies
 * every check on the resource rather than being skipped.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ResourcePolicyResolver
{
    /** @var string The column of an attachment holding the attached record's key, null for a type's. */
    private const string ATTACHED_KEY = '.resource_id';

    /** @var string The column of an attachment holding the attached policy's key. */
    private const string POLICY_KEY = '.policy_id';

    /** @var string The column of an attachment holding the attached resource's type. */
    private const string ATTACHED_TYPE = '.resource_type';

    /** @var string The column the query reads the attached resource's key into. */
    private const string RESOURCE_ID = 'attached_resource_id';

    /** @var int How many policies attached to records are read at a time. */
    private const int RECORD_PAGE = 100;

    /** @var int How many policies attached to records, whatever their actions, are scanned at most for each one the limit allows. */
    private const int RECORD_SCAN = 4;

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
     * Return the policies attached to each resource and to its type, keyed as
     * the resources are, exactly as `policiesFor()` returns them for each: the
     * records of one type are read in one query in the scope the call is made
     * in, and, for those of a tenant decided outside it, in one more in each
     * such tenant, through the resolution cache, which keeps each record's
     * entry. A record named more than once is read in the same query.
     *
     * @param  array<array-key, \SineMacula\Laravel\Authorization\Support\ResourceReference|null>  $resources
     * @return array<array-key, list<\SineMacula\Laravel\Authorization\Evaluation\Policy>>
     *
     * @throws \SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException
     */
    public function policiesForMany(array $resources): array
    {
        $outside  = self::outside($resources);
        $own      = [];
        $policies = [];

        // Read in each tenant decided outside first, so what is read in the
        // scope of the call is still in the cache once it returns.
        foreach ($outside as $tenantKey => [$tenant, $group]) {
            $own[$tenantKey] = TenantScope::within($tenant, TenantScope::currentApplication(), static fn (): array => self::readMany($group));
        }

        $read = self::readMany($resources);

        foreach ($resources as $key => $resource) {
            $entry = self::entryOf($resource);
            $found = $entry === null ? [] : $read[$entry];

            // Decided outside the resource's tenant, as in `policiesFor()`.
            $tenantKey      = $resource?->tenant === null ? null : $resource->tenant->type . "\0" . $resource->tenant->id;
            $denies         = $entry !== null && $tenantKey !== null && isset($outside[$tenantKey]) ? self::deniesOf($own[$tenantKey][$entry], $found) : [];
            $policies[$key] = [...$found, ...$denies];
        }

        return $policies;
    }

    /**
     * Return the policies attached to records of the type in the tenant and
     * application the check is decided in, those with a statement naming the
     * action, each once, as attached to the type's records, for an authorized
     * scope to compare each row's key with what they are attached to; or null
     * when more than the limit name the action, or more than `RECORD_SCAN`
     * times the limit are attached to records there whatever their actions, so
     * the read is bounded by the rows it scans as well as by what it keeps. The
     * attachments are read on the write connection, past the resolution cache,
     * so one made since the last check counts, a page at a time. A type longer
     * than the table stores has none.
     *
     * @param  string  $type
     * @param  string  $action
     * @param  int  $limit
     * @return list<\SineMacula\Laravel\Authorization\Evaluation\Policy>|null
     *
     * @throws \SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException
     */
    public function recordPoliciesFor(string $type, string $action, int $limit): ?array
    {
        if (\strlen($type) > Reference::MAX_BYTES) {
            return [];
        }

        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Policy> $class */
        $class = config('authorization.models.policy', Policy::class);

        /** @var string $table */
        $table = config('authorization.tables.resource_policies', 'resource_policies');

        $model    = new $class;
        $policies = $class::query()->withoutGlobalScopes()->useWritePdo()
            ->whereIn($model->getQualifiedKeyName(), static function (Builder $query) use ($table, $type): void {
                $query->select($table . self::POLICY_KEY)->from($table)->where($table . self::ATTACHED_TYPE, $type)->whereNotNull($table . self::ATTACHED_KEY);

                TenantScope::currentChain()->grants($query, $table);
                GrantApplications::only($query, $table, TenantScope::currentApplication());
            })
            ->lazyById(self::RECORD_PAGE);

        $names   = static fn (Statement $statement): bool => $statement->coversAction($action);
        $found   = [];
        $scanned = 0;

        foreach ($policies as $policy) {
            $hydrated = GrantResolver::hydrate($policy);

            if (\array_filter($hydrated->statements, $names) !== []) {
                $found[] = $hydrated->withResource("{$type}:*");
            }

            // More scanned than the limit's multiple, or more found than the
            // limit, without overflowing however large the limit is.
            if (\intdiv($scanned++, self::RECORD_SCAN) >= $limit || \count($found) > $limit) {
                return null;
            }
        }

        return $found;
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
            ->join($table, $table . self::POLICY_KEY, '=', $model->getQualifiedKeyName())
            ->where($table . self::ATTACHED_TYPE, $type)
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

        $hydrated = [];

        return new Resolution(self::hydrated($query->get()->all(), $type, $hydrated));
    }

    /**
     * Resolve the policies attached to each record of the type with the keys,
     * and to the type, keyed by the record's key, in one query, having pinned
     * the versions the type's attachments and every policy share, each policy's
     * document read once. A record whose policies include a document that
     * cannot be read is left out, so a check on it reads them on its own, and
     * that check alone is denied.
     *
     * @param  string  $type
     * @param  list<string>  $ids
     * @param  \SineMacula\Laravel\Authorization\Cache\ResolutionPins  $pins
     * @return array<array-key, \SineMacula\Laravel\Authorization\Cache\Resolution<\SineMacula\Laravel\Authorization\Evaluation\Policy>>
     */
    public static function resolveMany(string $type, array $ids, ResolutionPins $pins): array
    {
        $pins->resourcePolicies($type);

        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Policy> $class */
        $class = config('authorization.models.policy', Policy::class);

        /** @var string $table */
        $table = config('authorization.tables.resource_policies', 'resource_policies');

        $model = new $class;

        // The rows are told apart by their key in PHP, byte for byte, so a key
        // column that compares otherwise leaves every record to be read on its
        // own, under the column's own comparison.
        if (!self::isComparedExactly($model, $table)) {
            return [];
        }

        $rows = $class::query()->withoutGlobalScopes()->useWritePdo()
            ->join($table, $table . self::POLICY_KEY, '=', $model->getQualifiedKeyName())
            ->where($table . self::ATTACHED_TYPE, $type)
            ->where(static function (Builder $query) use ($table, $ids): void {
                $query->whereNull($table . self::ATTACHED_KEY)->orWhereIn($table . self::ATTACHED_KEY, $ids);
            })
            ->where(static function (Builder $query) use ($table): void {
                TenantScope::currentChain()->grants($query, $table);
                GrantApplications::only($query, $table, TenantScope::currentApplication());
            })
            ->select([$model->qualifyColumn('*'), $table . '.resource_id as ' . self::RESOURCE_ID])
            ->get()
            ->all();

        $byRecord = [];

        foreach ($rows as $row) {
            /** @var string|null $recordId */
            $recordId = $row->getAttribute(self::RESOURCE_ID);

            $byRecord[$recordId === null ? '' : "#{$recordId}"][] = $row;
        }

        $hydrated    = [];
        $resolutions = [];

        foreach ($ids as $id) {
            try {
                $resolutions[$id] = new Resolution(self::hydrated([...$byRecord[''] ?? [], ...$byRecord["#{$id}"] ?? []], $type, $hydrated));
            } catch (InvalidPolicyDocumentException) {
                continue;
            }
        }

        return $resolutions;
    }

    /**
     * Determine whether the attachments table compares a record's key byte for
     * byte, as PHP does, so a record's attachments can be told apart from
     * another's after they are read together.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $model
     * @param  string  $table
     * @return bool
     */
    private static function isComparedExactly(Policy $model, string $table): bool
    {
        $connection = $model->getConnection();
        $dialect    = Dialects::for($connection->getDriverName());

        /** @var \SineMacula\Laravel\Authorization\Query\SchemaInspector $inspector */
        $inspector = Container::getInstance()->make(SchemaInspector::class);

        return $dialect !== null && $inspector->isExactCollation($connection, $dialect, $table, 'resource_id');
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
     * Read the policies attached to each resource and to its type in the tenant
     * and application the call is made in, keyed by the entry each is read
     * under: those of the records of a type in one query, through the
     * resolution cache, and those of a type alone as `read()` reads them.
     *
     * @param  array<array-key, \SineMacula\Laravel\Authorization\Support\ResourceReference|null>  $resources
     * @return array<string, list<\SineMacula\Laravel\Authorization\Evaluation\Policy>>
     *
     * @throws \SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException
     */
    private static function readMany(array $resources): array
    {
        $records = [];
        $read    = [];
        $queued  = [];

        foreach ($resources as $resource) {
            $entry = self::entryOf($resource);

            // A record named more than once is read for once.
            if ($entry === null || $resource === null || isset($read[$entry]) || isset($queued[$entry])) {
                continue;
            }

            // A resource with an entry always has a type.
            /** @var string $type */
            $type = $resource->type;

            if (self::isReadInBulk($resource->id)) {
                $records["#{$type}"][0]   = $type;
                $records["#{$type}"][1][] = $resource->id;
                $queued[$entry]           = true;

                continue;
            }

            $read[$entry] = self::read($type, self::isStorableKey($resource->id) ? $resource->id : null);
        }

        foreach ($records as [$type, $ids]) {
            $read = [...$read, ...self::readRecords($type, $ids)];
        }

        return $read;
    }

    /**
     * Read the policies attached to each record of the type with the keys, and
     * to the type, in one query through the resolution cache, keyed by the
     * entry each is read under; a record the bulk read leaves out reads its
     * own.
     *
     * @param  string  $type
     * @param  list<string>  $ids
     * @return array<string, list<\SineMacula\Laravel\Authorization\Evaluation\Policy>>
     *
     * @throws \SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException
     */
    private static function readRecords(string $type, array $ids): array
    {
        $resolve = static fn (ResolutionPins $pins, array $missing): array => self::resolveMany($type, $missing, $pins);
        $found   = ResolutionCache::instance()?->rememberResourcePoliciesMany($type, $ids, $resolve)
            ?? \array_map(static fn (Resolution $resolution): array => $resolution->value, self::resolveMany($type, $ids, new ResolutionPins));
        $read = [];

        foreach ($ids as $id) {
            $read["{$type}\0{$id}"] = $found[$id] ?? self::read($type, $id);
        }

        return $read;
    }

    /**
     * Return the resources of a tenant a check on them is decided outside of,
     * in the scope the call is made in, grouped by their tenant, each group
     * with its tenant.
     *
     * @param  array<array-key, \SineMacula\Laravel\Authorization\Support\ResourceReference|null>  $resources
     * @return array<string, array{\SineMacula\Laravel\Authorization\Support\Reference, array<array-key, \SineMacula\Laravel\Authorization\Support\ResourceReference>}>
     */
    private static function outside(array $resources): array
    {
        $chain = TenantScope::currentChain();

        /** @var array<string, array{\SineMacula\Laravel\Authorization\Support\Reference, array<array-key, \SineMacula\Laravel\Authorization\Support\ResourceReference>}> $outside */
        $outside = [];

        foreach ($resources as $key => $resource) {
            $tenant = $resource?->tenant;

            if ($resource === null || $tenant === null || $chain->isAt($tenant) || self::entryOf($resource) === null) {
                continue;
            }

            $tenantKey = $tenant->type . "\0" . $tenant->id;

            $outside[$tenantKey] ??= [$tenant, []];
            $outside[$tenantKey][1][$key] = $resource;
        }

        return $outside;
    }

    /**
     * Return the entry a resource's attached policies are read under: its type
     * and its key, or its type alone when it has no key an attachment can name,
     * or null when it has no attached policies at all, as for no resource, an
     * opaque identifier or a type longer than the table stores.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference|null  $resource
     * @return string|null
     */
    private static function entryOf(?ResourceReference $resource): ?string
    {
        if ($resource === null || $resource->type === null || \strlen($resource->type) > Reference::MAX_BYTES) {
            return null;
        }

        return $resource->type . "\0" . (self::isStorableKey($resource->id) ? $resource->id : '*');
    }

    /**
     * Return the policy the row holds, hydrated once however many records it is
     * read for, or the exception its document threw, kept so it is thrown again
     * without hydrating again.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $row
     * @param  array<int, \SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException|\SineMacula\Laravel\Authorization\Evaluation\Policy>  $hydrated
     * @return \SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException|\SineMacula\Laravel\Authorization\Evaluation\Policy
     */
    private static function hydrateOnce(Policy $row, array &$hydrated): EvaluationPolicy|InvalidPolicyDocumentException
    {
        $id = \spl_object_id($row);

        try {
            $hydrated[$id] ??= GrantResolver::hydrate($row);
        } catch (InvalidPolicyDocumentException $exception) {
            $hydrated[$id] = $exception;
        }

        return $hydrated[$id];
    }

    /**
     * Determine whether a record's key is read in bulk: one an attachment can
     * name and UTF-8, since PostgreSQL refuses a key that is not, so such a key
     * is read on its own and fails its own read alone.
     *
     * @param  string|null  $id
     * @return bool
     *
     * @phpstan-assert-if-true string $id
     */
    private static function isReadInBulk(?string $id): bool
    {
        return self::isStorableKey($id) && \mb_check_encoding($id, 'UTF-8');
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
     * @param  array<int, \SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException|\SineMacula\Laravel\Authorization\Evaluation\Policy>  $hydrated
     * @return list<\SineMacula\Laravel\Authorization\Evaluation\Policy>
     *
     * @throws \SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException
     */
    private static function hydrated(array $rows, string $type, array &$hydrated): array
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
            $policy = self::hydrateOnce($row, $hydrated);

            $policies[] = $policy instanceof InvalidPolicyDocumentException ? throw $policy : $policy->withResource($resource);
        }

        return $policies;
    }
}
