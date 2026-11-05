<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;

/**
 * One call that changes the package's records, as every event it dispatches
 * reports it: an id shared by those events, for correlation, the actor the
 * caller named, and when the call was made.
 *
 * Each management service call is one operation, as is a write made through a
 * model outside the services, which names no actor.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Operation
{
    /**
     * Create a new operation.
     *
     * @param  string  $id
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @param  \DateTimeImmutable  $at
     */
    public function __construct(

        /** The operation's id, a UUID shared by every event it dispatches. */
        public string $id,

        /** Who made the call, as the caller named them; null for system work. */
        public ?Reference $actor,

        /** When the call was made, in UTC. */
        public \DateTimeImmutable $at,
    ) {}

    /**
     * Begin a new operation for the given actor, with a new id, now.
     *
     * @param  \Illuminate\Database\Eloquent\Model|\SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function begin(Model|Reference|null $actor = null): self
    {
        return new self((string) Str::uuid(), $actor === null ? null : Reference::of($actor), CarbonImmutable::now('UTC'));
    }
}
