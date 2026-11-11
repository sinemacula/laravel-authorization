<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Concerns;

use SineMacula\Laravel\Authorization\Evaluation\DecisionMemory;

/**
 * What the authorization manager forgets of the decisions of the current
 * request or job: the last decision alone, with `forgetLastDecision()`, or
 * everything remembered towards them, with `forgetDecisionsFor()` (N112).
 *
 * Neither is a decision, so neither refuses while the package is not healthy
 * (see `PackageState`): forgetting is always safe. Both clear the state every
 * scoped clone of the manager shares, never the subject a clone was scoped to.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait ForgetsDecisions
{
    /**
     * Clear the recorded last decision. Long-running workers call this between
     * requests so a stale decision does not leak across the request boundary.
     *
     * @return void
     */
    public function forgetLastDecision(): void
    {
        $this->lastDecisionStore->forget();
    }

    /**
     * Forget everything the request or job remembers towards its decisions, so
     * the rest of it decides afresh: what a suite package or the application
     * calls once a proof is recorded or revoked, a session signs in or out, or
     * the tenant is switched inside the request or job.
     *
     * The last decision, its provenance and the session it was recorded in are
     * cleared; the resolution cache's memo is emptied, in every scope, while
     * its persistent store and version keys are left as they are, since no
     * grant changed; and the tenant and application resolved for the request
     * are dropped, so the next check asks the subject resolver again for the
     * subject, its session and its tenant, while a scope put in place with
     * `TenantScope::within()` or an `AuthorizationScope` stays as its caller
     * set it. A batch of checks still running reads ahead again from its next
     * chunk, one about the request's subject asking the subject resolver for it
     * again, a preview admits its previewer again at its next decision, and
     * what limits a right is worked out again (see `DecisionMemory`). The
     * session caps are read from the session policy source at every check, so
     * nothing of them is held to forget. A manager from `for()` or `forUser()`
     * keeps its subject, and decides afresh about it, one from `for()` of a
     * `Subject` in the subject's own scope, even when that is the request's.
     *
     * The session and the identity name what changed, for the caller's clarity
     * and for a later version that forgets selectively: in this one, whatever
     * they are, null included, everything is forgotten, for every session and
     * every identity. A decision already returned and an event already
     * dispatched are observations of what was decided then, and are never
     * retracted. It is not a decision, so it never refuses, even while the
     * package does (see `PackageState`).
     *
     * @param  string|null  $session
     * @param  object|null  $identity
     * @return void
     */
    public function forgetDecisionsFor(?string $session = null, ?object $identity = null): void
    {
        DecisionMemory::current()->forget($this->lastDecisionStore);
    }
}
