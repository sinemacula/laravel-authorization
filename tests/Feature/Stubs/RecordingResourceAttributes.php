<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Contracts\ResourceAttributeProvider;
use SineMacula\Laravel\Authorization\Support\ResourceReference;

/**
 * A resource attribute provider declaring a status and an owner's id, which
 * records every record and model it is asked about and returns a key it does
 * not declare beside those it does.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordingResourceAttributes implements ResourceAttributeProvider
{
    /** @var list<array{\SineMacula\Laravel\Authorization\Support\ResourceReference, \Illuminate\Database\Eloquent\Model|null}> Each record asked about, with the model given. */
    public array $calls = [];

    /**
     * Create a new recording resource attribute provider.
     *
     * @param  string  $status
     */
    public function __construct(

        /** The status every record has. */
        public string $status = 'draft',
    ) {}

    /**
     * Return the attributes the provider declares.
     *
     * @return array<string, \SineMacula\Laravel\Authorization\Enums\ContextKeyType|string>
     */
    #[\Override]
    public function attributes(): array
    {
        return ['status' => 'string', 'owner.id' => 'string'];
    }

    /**
     * Return the record's attributes, recording the call.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference  $resource
     * @param  \Illuminate\Database\Eloquent\Model|null  $model
     * @return array<string, mixed>
     */
    #[\Override]
    public function values(ResourceReference $resource, ?Model $model): array
    {
        $this->calls[] = [$resource, $model];

        return ['status' => $this->status, 'owner' => ['id' => '7', 'email' => 'owner@example.com'], 'secret' => 'classified'];
    }
}
