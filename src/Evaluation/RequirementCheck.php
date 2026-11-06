<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

use Illuminate\Support\Carbon;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationRequirementChecker;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\AuthorizationLog;

/**
 * Judges the authentication requirements one check reads (N34), and records
 * what the decision may be reused for (N37).
 *
 * A requirement is met only when the checker says so for the subject's session:
 * with no checker, no subject, or a subject without a session, every part is
 * unmet and the checker is never asked. A met result whose instant has passed
 * is unmet, every part with it, and so is an unmet one that names none of the
 * requirement's parts; an unmet one keeps only the parts the requirement names.
 * A checker that throws makes the test undecidable; the failure is logged at
 * debug level by the checker's class and the exception's class alone, so no
 * proof reaches the log.
 *
 * Nothing is remembered between requirements: every requirement a statement
 * states is put to the checker afresh, so no unmet or undecidable result is
 * ever reused. Build one for every check, as its context is.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RequirementCheck
{
    /** @var bool Whether the check has read a requirement. */
    private bool $hasRead = false;

    /** @var \DateTimeImmutable|null The earliest instant a met requirement the check read stops being met. */
    private ?\DateTimeImmutable $metUntil = null;

    /**
     * Create a new requirement check.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\AuthenticationRequirementChecker|null  $checker
     * @param  \SineMacula\Laravel\Authorization\Subject|null  $subject
     */
    public function __construct(

        /** The checker that judges each requirement; null finds every requirement unmet. */
        private readonly ?AuthenticationRequirementChecker $checker = null,

        /** The subject the check is about, whose session the checker judges. */
        private readonly ?Subject $subject = null,
    ) {}

    /**
     * Assess the requirement for the check's subject: it holds when met,
     * definitely does not hold when unmet (carrying its unmet parts), and is
     * undecidable when the checker throws.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\AuthenticationRequirement  $requirement
     * @return \SineMacula\Laravel\Authorization\Evaluation\MatchResult
     */
    public function assess(AuthenticationRequirement $requirement): MatchResult
    {
        $this->hasRead = true;

        $result = $this->resultOf($requirement);

        if ($result === null) {
            return MatchResult::undecidable('the authentication requirement cannot be checked');
        }

        $unmet = $this->unmetOf($requirement, $result);

        return $unmet === [] ? MatchResult::matches() : MatchResult::unmet(new UnmetRequirement($requirement, $unmet));
    }

    /**
     * Return how long the decision may be reused, or null when the check read
     * no requirement, so nothing limits it.
     *
     * @return \SineMacula\Laravel\Authorization\Evaluation\RequirementFreshness|null
     */
    public function freshness(): ?RequirementFreshness
    {
        return $this->hasRead ? new RequirementFreshness($this->subject?->session, $this->metUntil) : null;
    }

    /**
     * Return what the checker found, every part unmet without asking it when
     * there is no checker or no session, or null when it throws.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\AuthenticationRequirement  $requirement
     * @return \SineMacula\Laravel\Authorization\Evaluation\RequirementResult|null
     */
    private function resultOf(AuthenticationRequirement $requirement): ?RequirementResult
    {
        if ($this->checker === null || $this->subject === null || $this->subject->session === null) {
            return RequirementResult::unmet($requirement->names());
        }

        try {
            return $this->checker->check($requirement, $this->subject);
        } catch (\Throwable $exception) {
            AuthorizationLog::debug('Authentication requirement checker ' . $this->checker::class . ' threw ' . $exception::class . ': the requirement is undecidable.');

            return null;
        }
    }

    /**
     * Return the parts of the requirement the result leaves unmet, none when it
     * is met and has not lapsed, recording the instant it stays met until.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\AuthenticationRequirement  $requirement
     * @param  \SineMacula\Laravel\Authorization\Evaluation\RequirementResult  $result
     * @return list<string>
     */
    private function unmetOf(AuthenticationRequirement $requirement, RequirementResult $result): array
    {
        if ($result->isMet && ($result->metUntil === null || $result->metUntil > Carbon::now())) {
            $this->metUntil = self::earliest($this->metUntil, $result->metUntil);

            return [];
        }

        $unmet = \array_values(\array_intersect($requirement->names(), $result->unmet));

        return $unmet === [] ? $requirement->names() : $unmet;
    }

    /**
     * Return the earlier of two instants, either of which may be absent.
     *
     * @param  \DateTimeImmutable|null  $first
     * @param  \DateTimeImmutable|null  $second
     * @return \DateTimeImmutable|null
     */
    private static function earliest(?\DateTimeImmutable $first, ?\DateTimeImmutable $second): ?\DateTimeImmutable
    {
        return $first === null || ($second !== null && $second < $first) ? $second : $first;
    }
}
