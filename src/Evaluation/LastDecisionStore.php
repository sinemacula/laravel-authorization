<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

/**
 * Single-slot holder for the most recent evaluation result. Shared by
 * reference across cloned manager scopes so `Authorization::lastDecision()`
 * observes decisions made through `for($user)->can(...)` chains. Each
 * `put()` replaces the prior value; no history is retained.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class LastDecisionStore
{
    /** @var \SineMacula\Laravel\Authorization\Evaluation\EvaluationResult|null Most recent result across any scope. */
    private ?EvaluationResult $last = null;

    /**
     * Store the supplied evaluation result as the most recent
     * decision, overwriting any prior value.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\EvaluationResult  $result
     * @return void
     */
    public function put(EvaluationResult $result): void
    {
        $this->last = $result;
    }

    /**
     * Return the most recent evaluation result, or null when the
     * process has not yet evaluated a decision (or the store was
     * explicitly cleared).
     *
     * @return \SineMacula\Laravel\Authorization\Evaluation\EvaluationResult|null
     */
    public function get(): ?EvaluationResult
    {
        return $this->last;
    }

    /**
     * Clear the recorded decision. Long-running workers (Octane,
     * RoadRunner) call this between requests to prevent a stale
     * decision from the previous request leaking into the next.
     *
     * @return void
     */
    public function forget(): void
    {
        $this->last = null;
    }

    /**
     * Reset the slot. Semantic alias of `forget()` intended for the
     * Octane / RoadRunner request-boundary listener wired by the
     * service provider.
     *
     * @return void
     */
    public function reset(): void
    {
        $this->forget();
    }
}
