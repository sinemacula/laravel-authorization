<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization;

use SineMacula\Laravel\Authorization\Evaluation\EvaluationResult;

/**
 * Single-slot holder for the most recent evaluation result.
 *
 * `AuthorizationManager::for()` and `withPolicies()` return cloned
 * manager instances. PHP's shallow copy semantics mean a property
 * on the manager itself would diverge between the root singleton
 * and every scoped clone — a `Authorization::lastDecision()` call
 * on the root would miss every decision made through a
 * `Authorization::for($user)->can(...)` chain.
 *
 * The store sidesteps that by living on a single shared object:
 * the clones inherit the same store reference via `clone`'s
 * shallow-copy semantics, and every `put()` overwrites the shared
 * slot. The facade accessor reads that slot regardless of which
 * scope produced the last decision.
 *
 * The class is intentionally a one-slot container, not a journal:
 * each `put()` replaces the prior value and no history is retained.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class LastDecisionStore
{
    /**
     * Most recent evaluation result captured from any manager scope.
     *
     * @var \SineMacula\Laravel\Authorization\Evaluation\EvaluationResult|null
     */
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
