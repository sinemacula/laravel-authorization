<?php

declare(strict_types = 1);

namespace Tests\Fixtures\BulkChecks;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Contracts\BulkResourceAttributeProvider;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\ResourceReference;

/**
 * A resource attribute provider of the guarded posts' status that reads them
 * through the tenant scope, one record at a time or many at once, keeping only
 * a post of no tenant or of exactly the tenant it is asked in, so what it finds
 * depends on the scope it is asked in, as an application's own provider reading
 * its scoped models, or the current tenant, does. Each call is recorded with
 * the scope it was made in.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class GuardedStatusAttributes implements BulkResourceAttributeProvider
{
    /** @var list<string> Each call, the keys it asked about, and the scope it was made in, in order. */
    public array $calls = [];

    /**
     * Return the attributes the provider declares.
     *
     * @return array<string, \SineMacula\Laravel\Authorization\Enums\ContextKeyType|string>
     */
    #[\Override]
    public function attributes(): array
    {
        return ['status' => 'string'];
    }

    /**
     * Return the record's status as the tenant scope lets it be read, recording
     * the call.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference  $resource
     * @param  \Illuminate\Database\Eloquent\Model|null  $model
     * @return array<string, mixed>
     */
    #[\Override]
    public function values(ResourceReference $resource, ?Model $model): array
    {
        $this->calls[] = 'one ' . $resource->id . ' in ' . TenantScope::scopeKey();

        return self::statusOf(GuardedPost::query()->find($resource->id), TenantScope::currentTenant());
    }

    /**
     * Return each item's status as the tenant scope lets it be read, in one
     * query, recording the call.
     *
     * @param  array<string, array{resource: \SineMacula\Laravel\Authorization\Support\ResourceReference, model: \Illuminate\Database\Eloquent\Model|null}>  $items
     * @return array<string, array<string, mixed>|\Throwable>
     */
    #[\Override]
    public function valuesMany(array $items): array
    {
        $ids = \array_values(\array_map(static fn (array $item): string => (string) $item['resource']->id, $items));

        $this->calls[] = 'many ' . \implode(',', $ids) . ' in ' . TenantScope::scopeKey();

        $records = GuardedPost::query()->whereKey($ids)->get()->getDictionary();
        $tenant  = TenantScope::currentTenant();

        return \array_map(static fn (array $item): array => self::statusOf($records[(string) $item['resource']->id] ?? null, $tenant), $items);
    }

    /**
     * Return the record's status when it has no tenant or is of exactly the
     * tenant given, or nothing.
     *
     * @param  \Illuminate\Database\Eloquent\Model|null  $record
     * @param  array{0: string, 1: string}|null  $tenant
     * @return array<string, mixed>
     */
    private static function statusOf(?Model $record, ?array $tenant): array
    {
        if ($record === null) {
            return [];
        }

        $tenantId = $record->getAttribute('tenant_id');
        $owner    = \is_int($tenantId) || \is_string($tenantId) ? [$record->getAttribute('tenant_type'), (string) $tenantId] : null;

        return $owner !== null && $owner !== $tenant ? [] : ['status' => $record->getAttribute('status')];
    }
}
