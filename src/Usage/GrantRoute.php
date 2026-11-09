<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Usage;

use SineMacula\Laravel\Authorization\Reviews\Enums\SourceKind;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * One grant route behind a permission or a policy a resolution found, as grant
 * usage tracking records it (N100): its key (see `GrantUsageKey`), the same key
 * an access review row of the same route carries, and the stored grant it
 * starts from (see `StoredGrant`).
 *
 * A resolution keeps the routes behind what it finds beside it in the
 * resolution cache, so a check finds those behind its decision from what the
 * cache holds, with no query.
 *
 * @phpstan-import-type Observation from \SineMacula\Laravel\Authorization\Usage\UsageBatch
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class GrantRoute
{
    /**
     * Create a new grant route.
     *
     * @param  string  $key
     * @param  \SineMacula\Laravel\Authorization\Usage\StoredGrant  $grant
     */
    public function __construct(

        /** The route's key, the same an access review row of the route carries. */
        public string $key,

        /** The stored grant the route starts from. */
        public StoredGrant $grant,
    ) {}

    /**
     * Return the route of the kind by which the stored grant reaches the
     * target, through the roles of the path.
     *
     * @param  \SineMacula\Laravel\Authorization\Reviews\Enums\SourceKind  $kind
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $target
     * @param  list<string>  $path
     * @param  \SineMacula\Laravel\Authorization\Usage\StoredGrant  $grant
     * @return self
     */
    public static function to(SourceKind $kind, Reference $target, array $path, StoredGrant $grant): self
    {
        return new self(GrantUsageKey::of($kind, $target, $grant->grantee, [$grant->tenantType, $grant->tenantId, $grant->application], $path), $grant);
    }

    /**
     * Return the observation of the route in the bucket starting at the
     * timestamp, as a usage batch carries it.
     *
     * @param  int  $bucket
     * @return Observation
     */
    public function observedIn(int $bucket): array
    {
        return ['grant_key' => $this->key, ...$this->grant->toArray(), 'last_observed_at' => $bucket];
    }

    /**
     * Return the route as the plain values a cache entry holds.
     *
     * @return array{key: string, grant: array<string, int|string|null>}
     */
    public function toArray(): array
    {
        return ['key' => $this->key, 'grant' => $this->grant->toArray()];
    }

    /**
     * Return the route the plain values describe, refusing values that do not
     * have its shape.
     *
     * @param  mixed  $values
     * @return self
     *
     * @throws \UnexpectedValueException
     */
    public static function fromArray(mixed $values): self
    {
        if (!\is_array($values) || !\is_string($values['key'] ?? null)) {
            throw new \UnexpectedValueException('A grant route is not the shape grant usage tracking keeps.');
        }

        return new self($values['key'], StoredGrant::fromArray($values['grant'] ?? null));
    }
}
