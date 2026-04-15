<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization;

use SineMacula\Laravel\Authorization\Evaluation\EvaluationResult;

/**
 * Shared holder for the most recent evaluation result.
 *
 * `AuthorizationManager::for()` and `withPolicies()` return cloned
 * manager instances. PHP's shallow copy semantics mean a property
 * on the manager itself would diverge between the root singleton
 * and every scoped clone — a `Authorization::lastDecision()` call
 * on the root would miss every decision made through a
 * `Authorization::for($user)->can(...)` chain.
 *
 * The journal sidesteps that by living on a single shared object:
 * the clones inherit the same journal reference via `clone`'s
 * shallow-copy semantics, and every `record()` updates the shared
 * state. The facade accessor reads that state regardless of which
 * scope produced the last decision.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class DecisionJournal
{
    /** Most recent evaluation result captured from any manager scope. */
    private ?EvaluationResult $last = null;

    /**
     * Record the supplied evaluation result as the most recent
     * decision.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\EvaluationResult  $result
     * @return void
     */
    public function record(EvaluationResult $result): void
    {
        $this->last = $result;
    }

    /**
     * Return the most recent evaluation result, or null when the
     * process has not yet evaluated a decision (or the journal was
     * explicitly cleared).
     *
     * @return \SineMacula\Laravel\Authorization\Evaluation\EvaluationResult|null
     */
    public function last(): ?EvaluationResult
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
}
