<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

/**
 * The evidence an explained check records beside its decision (N89): where each
 * grant that allowed it came from (see `GrantProvenance`), and what the check
 * asked (see `ExplanationRequest`). Each condition test the check made is
 * recorded on its trace (see `TraceEntry::$tests`).
 *
 * An everyday check records none, and costs what it did before explanations;
 * its decision explains with the evidence it has.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class DecisionEvidence
{
    /**
     * Create the evidence of an explained check.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Evaluation\GrantProvenance>  $grants
     * @param  \SineMacula\Laravel\Authorization\Evaluation\ExplanationRequest|null  $request
     */
    public function __construct(

        /** Where each grant that allowed the check came from, in order; none for a denial. */
        public array $grants = [],

        /** What the check asked; null when it was not captured. */
        public ?ExplanationRequest $request = null,
    ) {}

    /**
     * Return the evidence with what the check asked.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\ExplanationRequest  $request
     * @return self
     */
    public function withRequest(ExplanationRequest $request): self
    {
        return new self($this->grants, $request);
    }
}
