<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Contracts;

use SineMacula\Laravel\Authorization\Evaluation\AuthenticationRequirement;
use SineMacula\Laravel\Authorization\Evaluation\RequirementResult;
use SineMacula\Laravel\Authorization\Subject;

/**
 * Authentication requirement checker contract (AUTHZ-8.3, N34).
 *
 * Judges whether the subject's session meets an authentication requirement a
 * policy statement states, as one test: the checker fetches the session's
 * proofs itself, from the subject's `session`, and judges the newest proof that
 * meets each part, so a fresh weak proof and a stale strong one never meet a
 * requirement together. The package never passes proofs, or `amr`, in.
 *
 * The checker is asked only about a subject with a session: a check about a
 * subject without one (one the caller names, or one outside a session) finds
 * the requirement unmet without asking. The shipped resolver sets the session
 * only when that session signed in that very user, through a session guard
 * whose login key names it; a user set through `once()`, `onceUsingId()`,
 * `onceBasic()` or `setUser()`, or one a token or request guard returns, has
 * none. A checker should still confirm the proofs it finds belong to
 * `$subject->subject`, never judging another user's proofs. A checker that
 * throws makes the test undecidable, so an allow it guards does not apply and a
 * deny it guards does.
 *
 * The shipped default, `RefusingRequirementChecker`, finds every part unmet.
 * Under the suite it is `laravel-mfa`'s requirement check (AUTHZ-14.1).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface AuthenticationRequirementChecker
{
    /**
     * Judge the requirement for the subject's session: met, with the instant
     * until which it stays met when the checker knows it, or unmet, with the
     * parts that are not met.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\AuthenticationRequirement  $requirement
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return \SineMacula\Laravel\Authorization\Evaluation\RequirementResult
     *
     * @throws \Throwable
     */
    public function check(AuthenticationRequirement $requirement, Subject $subject): RequirementResult;
}
