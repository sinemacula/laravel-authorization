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

    /** @var string|null The session of the request that recorded the most recent decision, as its subject resolver gave it. */
    private ?string $session = null;

    /**
     * Store the supplied decision as the most recent one, with the session of
     * the request that recorded it (null outside one), overwriting any prior
     * value.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Decision  $decision
     * @param  string|null  $session
     * @return void
     */
    public function put(Decision $decision, ?string $session = null): void
    {
        $this->last    = $decision;
        $this->session = $session;
    }

    /**
     * Return the most recent decision, or null when the current request or job
     * has not yet evaluated a decision (or the store was explicitly cleared),
     * or when an authentication requirement the decision read has since stopped
     * being met (N37). Whether it was recorded in the current request's session
     * is for the reader to ask, with `wasRecordedIn()`.
     *
     * @return \SineMacula\Laravel\Authorization\Evaluation\Decision|null
     */
    public function get(): ?Decision
    {
        return $this->last?->freshness?->hasLapsed() === true ? null : $this->last;
    }

    /**
     * Determine whether the most recent decision was recorded in the session
     * given: the session of the request that recorded it, whatever subject the
     * decision was about.
     *
     * @param  string|null  $session
     * @return bool
     */
    public function wasRecordedIn(?string $session): bool
    {
        return $this->session === $session;
    }

    /**
     * Clear the recorded decision.
     *
     * @return void
     */
    public function forget(): void
    {
        $this->last    = null;
        $this->session = null;
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
