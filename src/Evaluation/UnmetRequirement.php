<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

/**
 * An authentication requirement that alone kept an allow statement from
 * applying, with the parts of it that are unmet (N35): one candidate of an
 * `insufficient_authentication` decision, which meeting would allow the check.
 *
 * It holds the requirement and the part names only: never the statement or the
 * policy that states it, nor any proof.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class UnmetRequirement
{
    /**
     * Create a new unmet requirement.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\AuthenticationRequirement  $requirement
     * @param  list<string>  $unmet
     */
    public function __construct(

        /** The requirement the statement states. */
        public AuthenticationRequirement $requirement,

        /** The name of each part of it that is not met. */
        public array $unmet,
    ) {}

    /**
     * Return the requirement, as a map of each part to its options, and the
     * parts unmet.
     *
     * @return array{requirement: array<string, array{max_age: int|null, min?: string}>, unmet: list<string>}
     */
    public function toArray(): array
    {
        return ['requirement' => $this->requirement->toArray(), 'unmet' => $this->unmet];
    }
}
