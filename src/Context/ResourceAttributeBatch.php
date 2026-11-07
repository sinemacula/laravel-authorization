<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Context;

use SineMacula\Laravel\Authorization\Contracts\BulkResourceAttributeProvider;
use SineMacula\Laravel\Authorization\Contracts\ResourceAttributeProvider;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use SineMacula\Laravel\Authorization\Support\ResourceScope;

/**
 * The resource attributes of a bulk check's records, read in bulk as its checks
 * first need them (AUTHZ-8.4, AUTHZ-10.3).
 *
 * Made for the records of a bulk check, each reference an item of its own under
 * a token, tracked a chunk at a time as each chunk starts, it reads nothing up
 * front. The first check on a record of a type that reads `resource` asks the
 * type's provider, when it reads in bulk (`BulkResourceAttributeProvider`), for
 * every record of that type still to be decided in the scope that check is
 * decided in (see `ResourceScope::scopeOf()`), so the provider is asked in the
 * very scope it would be asked in about each record on its own; a record
 * decided in another scope is read with the others of its scope, when the first
 * of them reads `resource`. A record the bulk read gives no answer for (its
 * provider does not read in bulk, the bulk call threw, or the answer left its
 * item out) is asked about on its own, once. Each item's answer, values or
 * failure, is kept for the checks on that item alone: an item's failure is
 * thrown only when a check on it reads `resource`, so it never touches another
 * item's decision.
 *
 * A reference shared by several checks, such as the one resource every action
 * of `permissionsFor()` is listed for, is one item, read once for all of them.
 * Each item is forgotten once the last check on it is decided, and its answer
 * released with it, so a record decided is never read for again.
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

    /** @var array<string, string|null> The key of the scope each item is decided in, by token, once told; null when it cannot be told. */
    private array $scopes = [];

    /** @var int How many items have been tracked, so each new item takes a token of its own. */
    private int $items = 0;

    /**
     * Create the batch of the records among the references, each an item of its
     * own, for a decision in the tenant given.
     *
     * @param  array<array-key, mixed>  $references
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $active
     */
    public function __construct(

        // The references of the first checks, each record among them an item.
        array $references = [],

        /** The tenant the checks are decided in, which tells the scope each record is decided in; null for none. */
        private readonly ?Reference $active = null,
    ) {
        $this->tokens = new \WeakMap;

        $this->track($references);
    }

    /**
     * Track the records among the references of the next checks, each an item
     * of its own; a reference already tracked stays the item it is.
     *
     * @param  array<array-key, mixed>  $references
     * @return void
     */
    public function track(array $references): void
    {
        foreach ($references as $reference) {
            if (!$reference instanceof ResourceReference || $reference->id === null || $reference->type === null || $this->tokens->offsetExists($reference)) {
                continue;
            }

            $token = 'item-' . $this->items++;

            $this->tokens[$reference] = $token;
            $this->pending[$token]    = $reference;
        }
    }

    /**
     * Return the values of the record: those the provider gave in bulk, reading
     * them now, with every record of its type still to be decided in its scope,
     * when they have not been read; or, when it gave none, those it gives for
     * the record on its own, asked once. An item's failure is thrown, for every
     * check on it. A record the batch does not track is asked about on its own.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference  $resource
     * @param  \SineMacula\Laravel\Authorization\Contracts\ResourceAttributeProvider  $provider
     * @return array<string, mixed>
     *
     * @throws \Throwable
     */
    public function valuesFor(ResourceReference $resource, ResourceAttributeProvider $provider): array
    {
        $token = $this->tokens[$resource] ?? null;

        if ($token === null) {
            return $provider->values($resource, $resource->model);
        }

        if (isset($this->pending[$token]) && $provider instanceof BulkResourceAttributeProvider) {
            $this->read($token, $provider);
        }

        $answer = $this->answers[$token] ??= self::attempt(static fn (): array => $provider->values($resource, $resource->model));

        return $answer instanceof \Throwable ? throw $answer : $answer;
    }

    /**
     * Forget the record once the last check on it is decided, with whatever was
     * read for it.
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

        unset($this->tokens[$reference], $this->pending[$token], $this->answers[$token], $this->scopes[$token]);
    }

    /**
     * Read the values of the item and of every other record of its type still
     * to be decided in its scope, in one call to the provider, keeping each
     * answer it gives for an item. A call that throws keeps none, so each
     * record is asked about on its own.
     *
     * @param  string  $token
     * @param  \SineMacula\Laravel\Authorization\Contracts\BulkResourceAttributeProvider  $provider
     * @return void
     */
    private function read(string $token, BulkResourceAttributeProvider $provider): void
    {
        $type  = $this->pending[$token]->type;
        $scope = $this->scopeOf($token);

        /** @var array<string, array{resource: \SineMacula\Laravel\Authorization\Support\ResourceReference, model: \Illuminate\Database\Eloquent\Model|null}> $items */
        $items = [];

        foreach ($this->pending as $pending => $reference) {
            // An item whose scope cannot be told is read alone.
            if ($pending !== $token && ($scope === null || $reference->type !== $type || $this->scopeOf($pending) !== $scope)) {
                continue;
            }

            $items[$pending] = ['resource' => $reference, 'model' => $reference->model];

            unset($this->pending[$pending]);
        }

        try {
            $answers = $provider->valuesMany($items);
        } catch (\Throwable) {
            return;
        }

        foreach (\array_keys($items) as $item) {
            $answer = $answers[$item] ?? null;

            if (!\is_array($answer) && !$answer instanceof \Throwable) {
                continue;
            }

            $this->answers[$item] = $answer;
        }
    }

    /**
     * Return the values the provider gives for the record on its own, or what
     * asking for them threw, kept as the item's answer either way.
     *
     * @param  \Closure(): array<string, mixed>  $read
     * @return array<string, mixed>|\Throwable
     */
    private static function attempt(\Closure $read): array|\Throwable
    {
        try {
            return $read();
        } catch (\Throwable $exception) {
            return $exception;
        }
    }

    /**
     * Return the key of the scope the item's check is decided in, told once, or
     * null when its tenant's place in the tree cannot be read, so it is read
     * with no other item: its check reads it again, and fails, on its own.
     *
     * @param  string  $token
     * @return string|null
     */
    private function scopeOf(string $token): ?string
    {
        if (!\array_key_exists($token, $this->scopes)) {
            try {
                $this->scopes[$token] = ResourceScope::scopeOf($this->pending[$token], $this->active);
            } catch (\Throwable) { // @phpstan-ignore catch.neverThrown (an application's tenant tree may throw)
                $this->scopes[$token] = null;
            }
        }

        return $this->scopes[$token];
    }
}
