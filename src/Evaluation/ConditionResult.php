<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

use SineMacula\Laravel\Authorization\Evaluation\Enums\ConditionOutcome;

/**
 * One condition test of a statement, as an explanation records it (AUTHZ-11.5):
 * the context key it tests, its operator, whether the `_if_exists` suffix lets
 * a missing key pass, what it found, whether the key was missing, and the
 * `${…}` references of its operand that could not be resolved, by key.
 *
 * Only an explained check records its tests, each on its own, so two tests of
 * one key stay apart. Never a value: no operand, no value read and no
 * interpolated string reaches it (AUTHZ-8.8).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ConditionResult
{
    /**
     * Create a new condition result.
     *
     * @param  string  $key
     * @param  string  $operator
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\ConditionOutcome  $outcome
     * @param  bool  $isOptional
     * @param  bool  $isMissing
     * @param  list<string>  $unresolved
     */
    public function __construct(

        /** The context key the test reads, `authentication` for an authentication requirement. */
        public string $key,

        /** The operator the test compares with, without its `_if_exists` suffix. */
        public string $operator,

        /** What the test found. */
        public ConditionOutcome $outcome,

        /** Whether the `_if_exists` suffix lets a missing key pass the test. */
        public bool $isOptional = false,

        /** Whether the key was missing from the context. */
        public bool $isMissing = false,

        /** The key of each `${…}` reference of the operand that could not be resolved, in order. */
        public array $unresolved = [],
    ) {}

    /**
     * Return the result as the explanation's JSON schema gives it.
     *
     * @return array{key: string, operator: string, if_exists: bool, outcome: string, missing: bool, unresolved: list<string>}
     */
    public function toArray(): array
    {
        return [
            'key'        => $this->key,
            'operator'   => $this->operator,
            'if_exists'  => $this->isOptional,
            'outcome'    => $this->outcome->value,
            'missing'    => $this->isMissing,
            'unresolved' => $this->unresolved,
        ];
    }
}
