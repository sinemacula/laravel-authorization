<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Contracts\ResourceAttributeProvider;
use SineMacula\Laravel\Authorization\Support\ResourceReference;

/**
 * A resource attribute provider declaring the keys it is constructed with, so a
 * test can declare a built-in, a key of another type than another provider
 * declares it, or a key that is not typed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ConflictingResourceAttributes implements ResourceAttributeProvider
{
    /**
     * Create a new resource attribute provider declaring the given keys.
     *
     * @param  array<array-key, mixed>  $declared
     */
    public function __construct(

        /** The keys the provider declares. */
        private array $declared = ['status' => 'number'],
    ) {}

    /**
     * Return the attributes the provider declares.
     *
     * @return array<string, \SineMacula\Laravel\Authorization\Enums\ContextKeyType|string>
     */
    #[\Override]
    public function attributes(): array
    {
        /** @var array<string, \SineMacula\Laravel\Authorization\Enums\ContextKeyType|string> */
        return $this->declared;
    }

    /**
     * Return no attributes.
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
}
