<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Context;

use SineMacula\Laravel\Authorization\Contracts\BulkResourceAttributeProvider;
use SineMacula\Laravel\Authorization\Contracts\ResourceAttributeProvider;
use SineMacula\Laravel\Authorization\Support\ResourceReference;

/**
 * The resource attributes of a bulk check's records, read in bulk as its checks
 * first need them (AUTHZ-8.4, AUTHZ-10.3).
 *
 * Made for the records of one chunk of a bulk check, each reference an item of
 * its own under a token, it reads nothing up front. The first check on a record
 * of a type that reads `resource` asks the type's provider, when it reads in
 * bulk (`BulkResourceAttributeProvider`), for every record of that type the
 * chunk still has to decide, and keeps each item's answer, values or failure,
 * for that item's check alone: an item's failure is thrown only when its own
 * check reads `resource`, so it never touches another's decision. A check the
 * batch holds no answer for (its provider does not read in bulk, the bulk call
 * threw, or the answer left its item out) asks the provider about its own
 * record, as a single check does.
 *
 * Each decided item is forgotten, and its answer released with it, so a check
 * decided is never read for again.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ResourceAttributeBatch
{
    /** @var \WeakMap<\SineMacula\Laravel\Authorization\Support\ResourceReference, string> The token of each record not yet decided. */
    private \WeakMap $tokens;

    /** @var array<string, \SineMacula\Laravel\Authorization\Support\ResourceReference> The records not yet read for, by token. */
    private array $pending = [];

    /** @var array<string, array<string, mixed>|\Throwable> The answer read for each item, by token. */
    private array $answers = [];

    /**
     * Create the batch of the records among the references, each an item of its
     * own.
     *
     * @param  array<array-key, mixed>  $references
     */
    public function __construct(array $references)
    {
        $this->tokens = new \WeakMap;

        foreach ($references as $reference) {
            if (!$reference instanceof ResourceReference || $reference->id === null || $reference->type === null || $this->tokens->offsetExists($reference)) {
                continue;
            }

            $token = 'item-' . \count($this->tokens);

            $this->tokens[$reference] = $token;
            $this->pending[$token]    = $reference;
        }
    }

    /**
     * Return the values the provider gave in bulk for the record, reading them
     * now, with every record of its type still to be decided, when they have
     * not been read; or null when there are none, so the provider is asked
     * about the record on its own. An item's failure is thrown.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference  $resource
     * @param  \SineMacula\Laravel\Authorization\Contracts\ResourceAttributeProvider  $provider
     * @return array<string, mixed>|null
     *
     * @throws \Throwable
     */
    public function valuesFor(ResourceReference $resource, ResourceAttributeProvider $provider): ?array
    {
        $token = $this->tokens[$resource] ?? null;

        if ($token === null || !$provider instanceof BulkResourceAttributeProvider) {
            return null;
        }

        if (isset($this->pending[$token])) {
            $this->read((string) $resource->type, $provider);
        }

        $answer = $this->answers[$token] ?? null;

        return $answer instanceof \Throwable ? throw $answer : $answer;
    }

    /**
     * Forget the record once its check is decided, with whatever was read for
     * it.
     *
     * @param  mixed  $reference
     * @return void
     */
    public function forget(mixed $reference): void
    {
        if (!$reference instanceof ResourceReference || !$this->tokens->offsetExists($reference)) {
            return;
        }

        $token = $this->tokens[$reference];

        unset($this->tokens[$reference], $this->pending[$token], $this->answers[$token]);
    }

    /**
     * Read the values of every record of the type still to be decided, in one
     * call to the provider, keeping each answer it gives for an item. A call
     * that throws keeps none, so each record is asked about on its own.
     *
     * @param  string  $type
     * @param  \SineMacula\Laravel\Authorization\Contracts\BulkResourceAttributeProvider  $provider
     * @return void
     */
    private function read(string $type, BulkResourceAttributeProvider $provider): void
    {
        /** @var array<string, array{resource: \SineMacula\Laravel\Authorization\Support\ResourceReference, model: \Illuminate\Database\Eloquent\Model|null}> $items */
        $items = [];

        foreach ($this->pending as $token => $reference) {
            if ($reference->type !== $type) {
                continue;
            }

            $items[$token] = ['resource' => $reference, 'model' => $reference->model];

            unset($this->pending[$token]);
        }

        try {
            $answers = $provider->valuesMany($items);
        } catch (\Throwable) {
            return;
        }

        foreach (\array_keys($items) as $token) {
            $answer = $answers[$token] ?? null;

            if (!\is_array($answer) && !$answer instanceof \Throwable) {
                continue;
            }

            $this->answers[$token] = $answer;
        }
    }
}
