<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exclusions;

use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * A holder that holds both roles of a pair of mutually exclusive roles where
 * their reach overlaps (AUTHZ-11.8, N136): one route to each role, which hold
 * in some tenant, or at the platform, in some application, together.
 *
 * The holder is the grantee of both routes, or, where the conflict came through
 * its identity, a principal holding one role itself and the other through its
 * identity, which is named too. References and scopes only, never a model.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ExclusionConflict
{
    /**
     * Create a new conflict.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $holder
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $identity
     * @param  \SineMacula\Laravel\Authorization\Exclusions\ExclusionRoute  $first
     * @param  \SineMacula\Laravel\Authorization\Exclusions\ExclusionRoute  $second
     */
    public function __construct(

        /** The principal or grantee that holds both roles. */
        public Reference $holder,

        /** The identity one of the routes came through; null when the holder holds both itself. */
        public ?Reference $identity,

        /** The route to the pair's first role. */
        public ExclusionRoute $first,

        /** The route to the pair's second role. */
        public ExclusionRoute $second,
    ) {}

    /**
     * Return the values the conflict is ordered by: its holder, its identity,
     * then its two routes.
     *
     * @return list<bool|string|null>
     */
    public function orderKey(): array
    {
        return [$this->holder->type, $this->holder->id, $this->identity?->type, $this->identity?->id, ...$this->first->orderKey(), ...$this->second->orderKey()];
    }
}
