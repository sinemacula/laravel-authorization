<?php

declare(strict_types = 1);

namespace Tests\Fixtures\BulkChecks;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Contracts\ResourceAttributeProvider;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use Tests\Fixtures\QueryScoping\ScopedPost;

/**
 * A resource attribute provider of the scoped posts' status that reads one
 * record at a time: the given model's status, or the record's, looked up,
 * failing for the records it is told to fail for.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class StatusAttributes implements ResourceAttributeProvider
{
    /** @var string The message a failure carries. */
    public const string MESSAGE = 'status lookup failed';

    /** @var list<string> The key of each record asked about, in order. */
    public array $calls = [];

    /** @var list<string> The keys of the records whose lookup fails. */
    public array $failing = [];

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

        $record = $model ?? ScopedPost::query()->find($resource->id);

        return $record === null ? [] : ['status' => $record->getAttribute('status')];
    }
}
