<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

/**
 * A policy statement, named by its policy and its position in it, with the
 * stored policy's key, since policies of different owners may share a name, and
 * the statement's `sid` when it has one.
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
     * @param  string|null  $sid
     */
    public function __construct(

        /** The name of the policy the statement belongs to. */
        public string $policy,

        /** The statement's position in the policy, from zero. */
        public int $index,

        /** The stored policy's key, which tells apart policies of one name; null for one built in code. */
        public ?string $policyId = null,

        /** The statement's id within its policy; null when it has none. It never changes how the statement is evaluated. */
        public ?string $sid = null,
    ) {}

    /**
     * Return the reference as text: the policy's name, its stored key when it
     * has one, the statement's position, and its sid, JSON-encoded, when it has
     * one: `name[key]#index sid="sid"`.
     *
     * @return string
     */
    public function toString(): string
    {
        $sid = $this->sid === null ? '' : ' sid=' . \json_encode($this->sid, \JSON_UNESCAPED_SLASHES | \JSON_INVALID_UTF8_SUBSTITUTE | \JSON_THROW_ON_ERROR);

        return $this->policy . ($this->policyId === null ? '' : "[{$this->policyId}]") . "#{$this->index}" . $sid;
    }
}
