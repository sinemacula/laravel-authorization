<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

/**
 * A policy statement, named by its policy and its position in it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class StatementReference
{
    /**
     * Create a new statement reference.
     *
     * @param  string  $policy
     * @param  int  $index
     */
    public function __construct(

        /** The name of the policy the statement belongs to. */
        public string $policy,

        /** The statement's position in the policy, from zero. */
        public int $index,
    ) {}

    /**
     * Return the reference as text: the policy's name and the statement's
     * position.
     *
     * @return string
     */
    public function toString(): string
    {
        return "{$this->policy}#{$this->index}";
    }
}
