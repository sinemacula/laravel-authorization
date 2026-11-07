<?php

declare(strict_types = 1);

namespace Tests\Fixtures\BulkChecks;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Contracts\BulkResourceAttributeProvider;
use SineMacula\Laravel\Authorization\Support\ResourceReference;

/**
 * A resource attribute provider that reads in bulk, answering each item with
 * the answer given for its record's key, whatever it is, and nothing for a key
 * it has no answer for, recording each call's items; broken, every call throws.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class AnsweringBulkAttributes implements BulkResourceAttributeProvider
{
    /** @var list<array<string, array{resource: \SineMacula\Laravel\Authorization\Support\ResourceReference, model: \Illuminate\Database\Eloquent\Model|null}>> Each call's items, in order. */
    public array $calls = [];

    /**
     * Create the provider.
     *
     * @param  array<string, mixed>  $answers
     * @param  bool  $isBroken
     */
    public function __construct(

        /** The answer for each record key. */
        private readonly array $answers,

        /** Whether every call throws. */
        private readonly bool $isBroken = false,
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
     * Return no values.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference  $resource
     * @param  \Illuminate\Database\Eloquent\Model|null  $model
     * @return array<string, mixed>
     */
    #[\Override]
    public function values(ResourceReference $resource, ?Model $model): array
    {
        return [];
    }

    /**
     * Return each item's answer, recording the call.
     *
     * @param  array<string, array{resource: \SineMacula\Laravel\Authorization\Support\ResourceReference, model: \Illuminate\Database\Eloquent\Model|null}>  $items
     * @return array<string, array<string, mixed>|\Throwable>
     *
     * @throws \RuntimeException
     */
    #[\Override]
    public function valuesMany(array $items): array
    {
        $this->calls[] = $items;

        if ($this->isBroken) {
            throw new \RuntimeException('broken');
        }

        $answers = [];

        foreach ($items as $token => $item) {
            $id = (string) $item['resource']->id;

            if (!\array_key_exists($id, $this->answers)) {
                continue;
            }

            $answers[$token] = $this->answers[$id];
        }

        /** @var array<string, array<string, mixed>|\Throwable> */
        return $answers;
    }
}
