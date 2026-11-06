<?php

declare(strict_types = 1);

namespace Tests\Fixtures\QueryScoping;

use SineMacula\Laravel\Authorization\Contracts\AuthenticationRequirementChecker;
use SineMacula\Laravel\Authorization\Contracts\ScopeInvariant;
use SineMacula\Laravel\Authorization\Evaluation\AuthenticationRequirement;
use SineMacula\Laravel\Authorization\Evaluation\RequirementResult;
use SineMacula\Laravel\Authorization\Subject;

/**
 * A requirement checker, marked `ScopeInvariant`, that finds every requirement
 * met or every part of it unmet, as it is told, for a subject with a session,
 * and unmet for any other, as the session's proofs would.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class InvariantRequirementChecker implements AuthenticationRequirementChecker, ScopeInvariant
{
    /**
     * Create a new checker.
     *
     * @param  bool  $isMet
     */
    public function __construct(

        /** Whether a subject with a session meets every requirement. */
        private bool $isMet,
    ) {}

    /**
     * Find the requirement met when told to and the subject has a session, and
     * every part of it unmet otherwise.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\AuthenticationRequirement  $requirement
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return \SineMacula\Laravel\Authorization\Evaluation\RequirementResult
     */
    #[\Override]
    public function check(AuthenticationRequirement $requirement, Subject $subject): RequirementResult
    {
        return $this->isMet && $subject->session !== null ? RequirementResult::met() : RequirementResult::unmet($requirement->names());
    }
}
