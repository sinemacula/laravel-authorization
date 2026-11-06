<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

/**
 * A policy statement, named by its policy and its position in it, with the
 * stored policy's key, since policies of different owners may share a name.
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
     * @param  string|null  $policyId
     */
    public function __construct(

        /** The name of the policy the statement belongs to. */
        public string $policy,

        /** The statement's position in the policy, from zero. */
        public int $index,

        /** The stored policy's key, which tells apart policies of one name; null for one built in code. */
        public ?string $policyId = null,
    ) {}

    /**
     * Return the reference as text: the policy's name, its stored key when it
     * has one, and the statement's position.
     *
     * @return string
     */
    public function toString(): string
    {
        return $this->policy . ($this->policyId === null ? '' : "[{$this->policyId}]") . "#{$this->index}";
    }
}
