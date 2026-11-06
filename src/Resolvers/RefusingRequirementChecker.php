<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Resolvers;

use SineMacula\Laravel\Authorization\Contracts\AuthenticationRequirementChecker;
use SineMacula\Laravel\Authorization\Contracts\ScopeInvariant;
use SineMacula\Laravel\Authorization\Evaluation\AuthenticationRequirement;
use SineMacula\Laravel\Authorization\Evaluation\RequirementResult;
use SineMacula\Laravel\Authorization\Subject;

/**
 * The default requirement checker: it knows no proofs, so every part of every
 * requirement is unmet, with no instant it is met until (N34). An allow that
 * states a requirement never applies until the application binds a checker.
 *
 * It is marked `ScopeInvariant`: it reads the request alone, never the record a
 * check is about, so `whereAuthorized()` reads it once for a query.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RefusingRequirementChecker implements AuthenticationRequirementChecker, ScopeInvariant
{
    /**
     * Find every part of the requirement unmet.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\AuthenticationRequirement  $requirement
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return \SineMacula\Laravel\Authorization\Evaluation\RequirementResult
     */
    #[\Override]
    public function check(AuthenticationRequirement $requirement, Subject $subject): RequirementResult
    {
        return RequirementResult::unmet($requirement->names());
    }
}
