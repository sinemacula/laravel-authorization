<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Contracts\ResourceAttributeProvider;
use SineMacula\Laravel\Authorization\Support\ResourceReference;

/**
 * A resource attribute provider that fails whenever it is asked for a record's
 * attributes, with a message holding a value no decision may carry.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class FailingResourceAttributes implements ResourceAttributeProvider
{
    /** @var string The message the failure carries. */
    public const string MESSAGE = 'lookup failed for owner@example.com';

    /** @var int How many times the provider was asked. */
    public int $calls = 0;

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
     * Fail to return the record's attributes.
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
        $this->calls++;

        throw new \RuntimeException(self::MESSAGE);
    }
}
