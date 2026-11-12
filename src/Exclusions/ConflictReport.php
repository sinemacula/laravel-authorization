<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exclusions;

use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Who holds both roles of a pair of mutually exclusive roles where their reach
 * overlaps (AUTHZ-11.8, N135, N136): one conflict for each pair of routes, one
 * to each role, that hold together somewhere, in a fixed order.
 *
 * The report is complete when the identity directory listed every principal of
 * every holder of either role completely; otherwise a principal holding one
 * role through an identity whose list left it out may be missing. Declaring a
 * pair is refused while its report holds any conflict, whether or not it is
 * complete. References and scopes only, never a model.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ConflictReport
{
    /**
     * Create a new conflict report.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $role
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $excludedRole
     * @param  list<\SineMacula\Laravel\Authorization\Exclusions\ExclusionConflict>  $conflicts
     * @param  bool  $isComplete
     */
    public function __construct(

        /** The pair's first role, the one with the lower key. */
        public Reference $role,

        /** The pair's second role, the one with the higher key. */
        public Reference $excludedRole,

        /** Each pair of overlapping routes, one to each role, held by one holder. */
        public array $conflicts = [],

        /** Whether the identity directory listed the principals of every holder completely. */
        public bool $isComplete = true,
    ) {}

    /**
     * Determine whether no one holds both roles where their reach overlaps.
     *
     * @return bool
     */
    public function isEmpty(): bool
    {
        return $this->conflicts === [];
    }

    /**
     * Return each holder that holds both roles, once, in the report's order.
     *
     * @return list<\SineMacula\Laravel\Authorization\Support\Reference>
     */
    public function holders(): array
    {
        $holders = [];

        foreach ($this->conflicts as $conflict) {
            $holders[\serialize([$conflict->holder->type, $conflict->holder->id])] = $conflict->holder;
        }

        return \array_values($holders);
    }
}
