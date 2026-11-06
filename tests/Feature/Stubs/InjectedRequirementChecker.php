<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use SineMacula\Laravel\Authorization\Contracts\AuthenticationRequirementChecker;
use SineMacula\Laravel\Authorization\Evaluation\AuthenticationRequirement;
use SineMacula\Laravel\Authorization\Evaluation\RequirementResult;
use SineMacula\Laravel\Authorization\Subject;

/**
 * A requirement checker the container builds from configuration, which meets
 * every requirement.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class InjectedRequirementChecker implements AuthenticationRequirementChecker
{
    /**
     * Meet the requirement.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\AuthenticationRequirement  $requirement
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return \SineMacula\Laravel\Authorization\Evaluation\RequirementResult
     */
    #[\Override]
    public function check(AuthenticationRequirement $requirement, Subject $subject): RequirementResult
    {
        return RequirementResult::met();
    }
}
