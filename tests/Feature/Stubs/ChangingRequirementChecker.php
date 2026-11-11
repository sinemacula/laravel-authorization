<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use SineMacula\Laravel\Authorization\Contracts\AuthenticationRequirementChecker;
use SineMacula\Laravel\Authorization\Evaluation\AuthenticationRequirement;
use SineMacula\Laravel\Authorization\Evaluation\RequirementResult;
use SineMacula\Laravel\Authorization\Subject;

/**
 * A requirement checker whose answer the test changes as the session's proofs
 * change, a step-up recorded or a proof revoked, counting each time it is
 * asked.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ChangingRequirementChecker implements AuthenticationRequirementChecker
{
    /** @var int How many times a requirement was judged. */
    public int $calls = 0;

    /**
     * Create a new changing requirement checker.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\RequirementResult  $answer
     */
    public function __construct(

        /** The result every requirement gets until the test changes it. */
        public RequirementResult $answer,
    ) {}

    /**
     * Return the current answer, counting the call.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\AuthenticationRequirement  $requirement
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return \SineMacula\Laravel\Authorization\Evaluation\RequirementResult
     */
    #[\Override]
    public function check(AuthenticationRequirement $requirement, Subject $subject): RequirementResult
    {
        $this->calls++;

        return $this->answer;
    }
}
