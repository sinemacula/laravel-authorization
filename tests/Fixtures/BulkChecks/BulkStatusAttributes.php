<?php

declare(strict_types = 1);

namespace Tests\Fixtures\BulkChecks;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Contracts\BulkResourceAttributeProvider;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use Tests\Fixtures\QueryScoping\ScopedPost;

/**
 * A resource attribute provider of the scoped posts' status that reads many
 * records at once: each given model's status, and the records' of the rest in
 * one query, as one record at a time would; failing for the records it is told
 * to fail for, or, broken, for the whole call.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class BulkStatusAttributes implements BulkResourceAttributeProvider
{
    /** @var string The message a failure carries. */
    public const string MESSAGE = 'status lookup failed';

    /** @var list<string> The key of each record asked about on its own, in order. */
    public array $calls = [];

    /** @var list<list<string>> The keys of the records of each bulk call, in order. */
    public array $bulkCalls = [];

    /** @var list<string> The keys of the records whose lookup fails. */
    public array $failing = [];

    /** @var bool Whether every bulk call fails. */
    public bool $isBroken = false;

    /** @var list<string> The keys of the records a bulk call leaves out. */
    public array $leftOut = [];

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
     * Return the record's status, recording the call.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference  $resource
     * @param  \Illuminate\Database\Eloquent\Model|null  $model
     * @return array<string, mixed>
     *
     * @throws \RuntimeException
     */
    #[\Override]
    public function values(ResourceReference $resource, ?Model $model): array
    {
        $this->calls[] = (string) $resource->id;

        if (\in_array($resource->id, $this->failing, true)) {
            throw new \RuntimeException(self::MESSAGE);
        }

        return self::statusOf($model ?? ScopedPost::query()->find($resource->id));
    }

    /**
     * Return each item's status, reading the records without a model in one
     * query, recording the call.
     *
     * @param  array<string, array{resource: \SineMacula\Laravel\Authorization\Support\ResourceReference, model: \Illuminate\Database\Eloquent\Model|null}>  $items
     * @return array<string, array<string, mixed>|\Throwable>
     *
     * @throws \RuntimeException
     */
    #[\Override]
    public function valuesMany(array $items): array
    {
        $this->bulkCalls[] = \array_values(\array_map(static fn (array $item): string => (string) $item['resource']->id, $items));

        if ($this->isBroken) {
            throw new \RuntimeException(self::MESSAGE);
        }

        $records = self::records($items);
        $values  = [];

        foreach ($items as $token => $item) {
            $id = (string) $item['resource']->id;

            if (\in_array($id, $this->leftOut, true)) {
                continue;
            }

            $values[$token] = \in_array($id, $this->failing, true) ? new \RuntimeException(self::MESSAGE) : self::statusOf($item['model'] ?? $records[$id] ?? null);
        }

        return $values;
    }

    /**
     * Return the records of the items given no model, read in one query, keyed
     * by their key.
     *
     * @param  array<string, array{resource: \SineMacula\Laravel\Authorization\Support\ResourceReference, model: \Illuminate\Database\Eloquent\Model|null}>  $items
     * @return array<array-key, \Illuminate\Database\Eloquent\Model>
     */
    private static function records(array $items): array
    {
        $ids = [];

        foreach ($items as $item) {
            if ($item['model'] !== null) {
                continue;
            }

            $ids[] = (string) $item['resource']->id;
        }

        return $ids === [] ? [] : ScopedPost::query()->whereKey($ids)->get()->getDictionary();
    }

    /**
     * Return the record's status, or nothing for no record.
     *
     * @param  \Illuminate\Database\Eloquent\Model|null  $record
     * @return array<string, mixed>
     */
    private static function statusOf(?Model $record): array
    {
        return $record === null ? [] : ['status' => $record->getAttribute('status')];
    }
}
