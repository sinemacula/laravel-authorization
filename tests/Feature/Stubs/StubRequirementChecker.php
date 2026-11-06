<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use SineMacula\Laravel\Authorization\Contracts\AuthenticationRequirementChecker;
use SineMacula\Laravel\Authorization\Evaluation\AuthenticationRequirement;
use SineMacula\Laravel\Authorization\Evaluation\RequirementResult;
use SineMacula\Laravel\Authorization\Subject;

/**
 * A requirement checker that answers every requirement with the result given,
 * or throws the exception given, recording each requirement and subject it is
 * asked about.
 *
 * With a result per part list, keyed by the requirement's part names joined by
 * `,`, a requirement listed there gets its own result.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class StubRequirementChecker implements AuthenticationRequirementChecker
{
    /** @var list<array{\SineMacula\Laravel\Authorization\Evaluation\AuthenticationRequirement, \SineMacula\Laravel\Authorization\Subject}> Each call. */
    public array $calls = [];

    /**
     * Create a new stub requirement checker.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\RequirementResult|\Throwable  $answer
     * @param  array<string, \SineMacula\Laravel\Authorization\Evaluation\RequirementResult>  $byParts
     */
    public function __construct(

        /** The result every requirement gets, or what the checker throws. */
        private readonly RequirementResult|\Throwable $answer,

        /** The result of each requirement whose part names, joined by `,`, are listed. */
        private readonly array $byParts = [],
    ) {}

    /**
     * Return the result given, or throw the exception given.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\AuthenticationRequirement  $requirement
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return \SineMacula\Laravel\Authorization\Evaluation\RequirementResult
     *
     * @throws \Throwable
     */
    #[\Override]
    public function check(AuthenticationRequirement $requirement, Subject $subject): RequirementResult
    {
        $this->calls[] = [$requirement, $subject];

        $answer = $this->byParts[\implode(',', $requirement->names())] ?? $this->answer;

        if ($answer instanceof \Throwable) {
            throw $answer;
        }

        return $answer;
    }
}
