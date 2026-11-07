<?php

declare(strict_types = 1);

namespace Tests\Fixtures\BulkChecks;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Contracts\BulkResourceAttributeProvider;
use SineMacula\Laravel\Authorization\Support\ResourceReference;

/**
 * A resource attribute provider that reads in bulk, giving every record one
 * status, and an undeclared key, whether asked in bulk or on its own, recording
 * every call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class FixedBulkAttributes implements BulkResourceAttributeProvider
{
    /** @var list<string> The key of each record asked about on its own, in order. */
    public array $calls = [];

    /** @var list<list<string>> The tokens of each bulk call, in order. */
    public array $bulkCalls = [];

    /**
     * Create a new provider giving every record the status.
     *
     * @param  string  $status
     * @param  string  $single
     */
    public function __construct(

        /** The status every record has when read in bulk. */
        private readonly string $status = 'published',

        /** The status every record has when read on its own. */
        private readonly string $single = 'draft',
    ) {}

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
     * Return the record's status read on its own, recording the call.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference  $resource
     * @param  \Illuminate\Database\Eloquent\Model|null  $model
     * @return array<string, mixed>
     */
    #[\Override]
    public function values(ResourceReference $resource, ?Model $model): array
    {
        $this->calls[] = (string) $resource->id;

        return ['status' => $this->single, 'secret' => 'classified'];
    }

    /**
     * Return each item's status read in bulk, recording the call.
     *
     * @param  array<string, array{resource: \SineMacula\Laravel\Authorization\Support\ResourceReference, model: \Illuminate\Database\Eloquent\Model|null}>  $items
     * @return array<string, array<string, mixed>|\Throwable>
     */
    #[\Override]
    public function valuesMany(array $items): array
    {
        $this->bulkCalls[] = \array_keys($items);

        return \array_map(fn (): array => ['status' => $this->status, 'secret' => 'classified'], $items);
    }
}
