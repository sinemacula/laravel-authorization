<?php

declare(strict_types = 1);

namespace Tests\Fixtures\BulkChecks;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Contracts\BulkResourceTenantResolver;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * A resource tenant resolver that answers in bulk from a fixed map of record
 * keys to tenants, recording every call: a key it does not know has no record,
 * one it is told to fail on throws, and, broken, every bulk call throws.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CountingBulkTenants implements BulkResourceTenantResolver
{
    /** @var string The message a failure carries. */
    public const string MESSAGE = 'tenant lookup failed';

    /** @var list<string> The key of each model or record asked about on its own, in order. */
    public array $calls = [];

    /** @var list<list<string>> The keys of each bulk call, in order. */
    public array $bulkCalls = [];

    /** @var list<string> The keys whose lookup throws. */
    public array $failing = [];

    /** @var bool Whether every bulk call throws. */
    public bool $isBroken = false;

    /** @var list<string> The keys a bulk call leaves out of its answer, each answered on its own. */
    public array $leftOut = [];

    /**
     * Create a new resolver answering from the map.
     *
     * @param  array<array-key, \SineMacula\Laravel\Authorization\Support\Reference|null>  $tenants
     */
    public function __construct(

        /** The tenant of each record key; a key left out has no record. */
        private readonly array $tenants = [],
    ) {}

    /**
     * Return the model's tenant from the map, recording the call.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $resource
     * @return \SineMacula\Laravel\Authorization\Support\Reference|null
     *
     * @throws \RuntimeException
     */
    #[\Override]
    public function tenantOf(Model $resource): ?Reference
    {
        $answer = $this->answer((string) $resource->getKey()); // @phpstan-ignore cast.string

        return $answer === false ? null : $answer;
    }

    /**
     * Return the record's tenant from the map, false for a key it does not
     * know, recording the call.
     *
     * @param  string  $type
     * @param  string  $id
     * @return false|\SineMacula\Laravel\Authorization\Support\Reference|null
     *
     * @throws \RuntimeException
     */
    #[\Override]
    public function tenantOfRecord(string $type, string $id): false|Reference|null
    {
        return $this->answer($id);
    }

    /**
     * Return each model's tenant, recording the call.
     *
     * @param  array<array-key, \Illuminate\Database\Eloquent\Model>  $models
     * @return array<array-key, \SineMacula\Laravel\Authorization\Support\Reference|null>
     *
     * @throws \RuntimeException
     */
    #[\Override]
    public function tenantsOf(array $models): array
    {
        $keys = \array_map(static fn (Model $model): string => (string) $model->getKey(), $models); // @phpstan-ignore cast.string

        $this->bulkCalls[] = \array_values($keys);

        $tenants = $this->isBroken ? throw new \RuntimeException(self::MESSAGE) : \array_map(fn (string $key): ?Reference => $this->tenants[$key] ?? null, $keys);

        return \array_diff_key($tenants, \array_intersect($keys, $this->leftOut));
    }

    /**
     * Return each record's tenant, false for a key it does not know, leaving
     * out the keys it fails on, recording the call.
     *
     * @param  string  $type
     * @param  array<array-key, string>  $ids
     * @return array<array-key, false|\SineMacula\Laravel\Authorization\Support\Reference|null>
     *
     * @throws \RuntimeException
     */
    #[\Override]
    public function tenantsOfRecords(string $type, array $ids): array
    {
        $this->bulkCalls[] = \array_values($ids);

        if ($this->isBroken) {
            throw new \RuntimeException(self::MESSAGE);
        }

        $tenants = \array_map(fn (string $id): false|Reference|null => \array_key_exists($id, $this->tenants) ? $this->tenants[$id] : false, $ids);

        return \array_diff_key($tenants, \array_intersect($ids, [...$this->failing, ...$this->leftOut]));
    }

    /**
     * Return the tenant of the key, recording the call: false when it is not in
     * the map, a failure when it is one of those failing.
     *
     * @param  string  $key
     * @return false|\SineMacula\Laravel\Authorization\Support\Reference|null
     *
     * @throws \RuntimeException
     */
    private function answer(string $key): false|Reference|null
    {
        $this->calls[] = $key;

        if (\in_array($key, $this->failing, true)) {
            throw new \RuntimeException(self::MESSAGE);
        }

        return \array_key_exists($key, $this->tenants) ? $this->tenants[$key] : false;
    }
}
