<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

/**
 * Single-slot holder for the most recent decision, with its provenance: who it
 * was about, who previewed it, and where it was made. Shared by reference
 * across cloned manager scopes so `Authorization::lastDecision()` observes
 * decisions made through `for($user)->can(...)` chains. Each `put()` replaces
 * the prior value; no history is retained. The service provider binds it with
 * `scoped()`, so the slot belongs to the current request or job.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class LastDecisionStore
{
    /** @var \SineMacula\Laravel\Authorization\Evaluation\Decision|null Most recent decision across any scope. */
    private ?Decision $last = null;

    /** @var \SineMacula\Laravel\Authorization\Evaluation\DecisionProvenance|null Who the most recent decision was about, who previewed it, and where it was made. */
    private ?DecisionProvenance $provenance = null;

    /** @var string|null The session of the request that recorded the most recent decision, as its subject resolver gave it. */
    private ?string $session = null;

    /**
     * Store the supplied decision as the most recent one, with its provenance
     * and the session of the request that recorded it (null outside one),
     * overwriting any prior value.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Decision  $decision
     * @param  \SineMacula\Laravel\Authorization\Evaluation\DecisionProvenance  $provenance
     * @param  string|null  $session
     * @return void
     */
    public function put(Decision $decision, DecisionProvenance $provenance, ?string $session = null): void
    {
        $this->last       = $decision;
        $this->provenance = $provenance;
        $this->session    = $session;
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
     * Return the provenance of the most recent decision recorded, or null when
     * none is. It is that of the decision last put, whether or not `get()`
     * still returns it, so a reader asks `get()` first.
     *
     * @return \SineMacula\Laravel\Authorization\Evaluation\DecisionProvenance|null
     */
    public function provenance(): ?DecisionProvenance
    {
        return $this->provenance;
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
     * Clear the recorded decision and its provenance.
     *
     * @return void
     */
    public function forget(): void
    {
        $this->last       = null;
        $this->provenance = null;
        $this->session    = null;
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
