<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

/**
 * Single-slot holder for the most recent decision. Shared by reference across
 * cloned manager scopes so `Authorization::lastDecision()` observes decisions
 * made through `for($user)->can(...)` chains. Each `put()` replaces the prior
 * value; no history is retained. The service provider binds it with `scoped()`,
 * so the slot belongs to the current request or job.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class LastDecisionStore
{
    /** @var \SineMacula\Laravel\Authorization\Evaluation\Decision|null Most recent decision across any scope. */
    private ?Decision $last = null;

    /**
     * Store the supplied decision as the most recent one, overwriting any prior
     * value.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Decision  $decision
     * @return void
     */
    public function put(Decision $decision): void
    {
        $this->last = $decision;
    }

    /**
     * Return the most recent decision, or null when the current request or job
     * has not yet evaluated a decision (or the store was explicitly cleared).
     *
     * @return \SineMacula\Laravel\Authorization\Evaluation\Decision|null
     */
    public function get(): ?Decision
    {
        return $this->last;
    }

    /**
     * Clear the recorded decision.
     *
     * @return void
     */
    public function forget(): void
    {
        $this->last = null;
    }

    /**
     * Reset the slot. Semantic alias of `forget()`.
     *
     * @return void
     */
    public function reset(): void
    {
        $this->forget();
    }
}
