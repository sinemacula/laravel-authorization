<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome;
use SineMacula\Laravel\Authorization\Evaluation\Enums\TraceOutcome;

/**
 * Decides a check from its statements, stage by stage (AUTHZ-7.1): the denies,
 * the caps (guardrails, permission boundaries and session caps), then the
 * allows, then the implicit deny. No allow is reached before every deny and
 * every cap has run, so a deny, or a cap that does not allow the check, beats
 * every allow source: a policy's allow, a resource policy's, a permission held
 * and an insufficient authentication alike.
 *
 * 1. *Deny*: every deny statement of every policy, every guardrail and every
 *    boundary is assessed, each in a fixed order (the policies by name, each
 *    statement by its position; see `StatementEntries`) and recorded in the
 *    trace, so the decision, its trace and the statements that decided it are
 *    the same whatever order the policies were read in (AUTHZ-7.9). An explicit
 *    deny wins over any allow, and nothing after it is assessed (N4).
 * 2. *Guardrail*: each guardrail on the check's tenant, its ancestors and the
 *    platform must allow the check, as its allow statements would as an
 *    ordinary policy's, conditions included. The guardrails are intersected:
 *    one that does not allow the check, one with no allow statement included,
 *    denies it as `guardrail`, with a step that names it, and with none the
 *    stage caps nothing. A guardrail grants nothing. A check exempt from the
 *    guardrails, as the caller says by giving none at all, skips the stage: no
 *    guardrail's deny or allow statement is weighed, and the stage records that
 *    the check is exempt.
 * 3. *Boundary*: each boundary of the subject's principal and identity must
 *    allow the check, as its allow statements would as an ordinary policy's,
 *    conditions included. The boundaries are intersected: one that does not
 *    allow the check, one with no allow statement included, denies it as
 *    `boundary`, with a step that names it, and with none the stage caps
 *    nothing. A boundary grants nothing: passing it only lets the allows be
 *    weighed.
 * 4. *Session*: no session cap applies yet (BL-50); the stage records that it
 *    capped nothing.
 * 5. *Allow*: every allow statement is assessed; failing an allow, a permission
 *    the subject holds allows, asked through the callback the caller gives,
 *    once, and only when no statement allowed and none was invalid.
 * 6. *Implicit*: nothing allowed. The denial is `insufficient_authentication`
 *    when an allow statement names the action and the resource and only its
 *    authentication requirement is unmet (N35), with each such requirement and
 *    its unmet parts as alternatives; `condition_failed` when an allow
 *    statement names them but its conditions do not hold; and `no_match`
 *    otherwise.
 *
 * Every stage the decision reaches is recorded in its trace: each statement it
 * assessed, the permission step, a step naming each guardrail and boundary that
 * refused the check, a step for a cap stage that capped nothing, and one for a
 * cap stage the check is exempt from.
 *
 * The evaluator fails closed: a deny statement applies when its test cannot be
 * decided (a missing context key, an unresolved `${…}` reference), and a
 * statement that cannot be evaluated denies the check as an invalid policy at
 * the stage that found it, so no fault in a statement ever skips a deny or a
 * cap. On a deny statement an unmet requirement is a test that does not hold,
 * so the deny does not apply, and one that cannot be checked applies it, as any
 * undecidable test does. On a guardrail's or a boundary's allow an unmet
 * requirement keeps the cap from allowing, so a cap that refuses is never
 * answered with a step-up.
 *
 * A policy attached to a resource (AUTHZ-7.3) is decided with the others: its
 * denies apply to everyone at the deny stage, and its allows only to a subject
 * their `principals` name, at the allow stage, with no permission held. An
 * allow that does not apply to the subject, a guardrail's or a boundary's
 * included, is recorded as a principal mismatch and bears on nothing, an unmet
 * authentication requirement included.
 *
 * A decision that read a requirement carries how long it may be reused: in the
 * session it was made in, until the earliest instant a met requirement it read
 * stops being met (N37).
 *
 * @phpstan-import-type StatementEntry from \SineMacula\Laravel\Authorization\Evaluation\StatementEntries
 * @phpstan-import-type Gathered from \SineMacula\Laravel\Authorization\Evaluation\StatementEntries
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class PolicyEvaluator
{
    /** @var string A statement that denies the check. */
    private const string DENY = 'deny';

    /** @var string A statement that cannot be evaluated. */
    private const string INVALID = 'invalid';

    /** @var string A statement that allows the check. */
    private const string ALLOW = 'allow';

    /** @var string An allow statement that names the check but whose conditions do not hold. */
    private const string FAILED = 'failed';

    /** @var string An allow statement that names the check and whose authentication requirement alone does not hold. */
    private const string INSUFFICIENT = 'insufficient';

    /** @var string A statement that does not bear on the check. */
    private const string NONE = 'none';

    /** @var \SineMacula\Laravel\Authorization\Evaluation\ContextInterpolator|null Lazily created interpolator. */
    private ?ContextInterpolator $interpolator = null;

    /** @var \SineMacula\Laravel\Authorization\Evaluation\StatementEntries|null Each policy's statements, worked out once per policy. */
    private ?StatementEntries $entries = null;

    /** @var array<string, \SineMacula\Laravel\Authorization\Evaluation\TraceEntry> The step each cap stage adds when it caps nothing, or the check is exempt from it, made once. */
    private array $passed = [];

    /**
     * Decide the check from the statements of the policies, the boundaries and
     * the guardrails.
     *
     * The context is the check's own: every statement of the check reads the
     * same one, which builds each namespace the first time a statement reads
     * it. A context given as an array is the check's namespaces, already built,
     * so what a caller passes belongs under `input`, where the check context
     * factory holds it, and the subject and resource under `subject` and
     * `resource`; the resource identifier is what resource patterns match.
     *
     * The boundaries are the permission boundaries that apply to the check, and
     * the guardrails the guardrails that do, each of which must allow it; null
     * guardrails exempt the check from the guardrail stage, their denies
     * included. The permission callback answers whether the subject holds a
     * permission the action names; with none, no permission is consulted.
     *
     * @param  array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>  $policies
     * @param  string  $action
     * @param  string|null  $resource
     * @param  array<array-key, mixed>|\SineMacula\Laravel\Authorization\Evaluation\CheckContext  $context
     * @param  array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>  $boundaries
     * @param  (\Closure(): bool)|null  $permission
     * @param  array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>|null  $guardrails
     * @return \SineMacula\Laravel\Authorization\Evaluation\Decision
     */
    public function evaluate(
        array $policies,
        string $action,
        ?string $resource = null,
        array|CheckContext $context = [],
        array $boundaries = [],
        ?\Closure $permission = null,
        ?array $guardrails = [],
    ): Decision {
        $context    = CheckContext::from($context);
        $statements = ($this->entries ??= new StatementEntries)->of($policies, $boundaries, $guardrails);

        return $this->decide($statements, $action, $resource, $context, $permission)->withFreshness($context->requirementFreshness());
    }

    /**
     * Decide the check from the statements, stage by stage: the denies, then
     * the caps, then the allows.
     *
     * @param  Gathered  $statements
     * @param  string  $action
     * @param  string|null  $resource
     * @param  \SineMacula\Laravel\Authorization\Evaluation\CheckContext  $context
     * @param  (\Closure(): bool)|null  $permission
     * @return \SineMacula\Laravel\Authorization\Evaluation\Decision
     */
    private function decide(array $statements, string $action, ?string $resource, CheckContext $context, ?\Closure $permission): Decision
    {
        $trace    = [];
        [$denies] = $this->assess($statements[self::DENY], DecisionStage::DENY, $action, $resource, $context, $trace);

        if ($denies[self::DENY] !== [] || $denies[self::INVALID] !== []) {
            return self::conclude(DecisionStage::DENY, $denies, [], $trace);
        }

        $capped = $this->cap($statements, $action, $resource, $context, $trace);

        return $capped ?? $this->allow($statements[self::ALLOW], $action, $resource, $context, $permission, $trace);
    }

    /**
     * Run the cap stages in order, guardrails, boundaries, then session caps,
     * and return the denial of the first that does not allow the check, or null
     * when none caps it, adding each stage's steps to the trace.
     *
     * Session caps (BL-50) take their place here as they arrive; until then the
     * stage records that it capped nothing.
     *
     * @param  Gathered  $statements
     * @param  string  $action
     * @param  string|null  $resource
     * @param  \SineMacula\Laravel\Authorization\Evaluation\CheckContext  $context
     * @param  list<\SineMacula\Laravel\Authorization\Evaluation\TraceEntry>  $trace
     *
     * @param-out list<\SineMacula\Laravel\Authorization\Evaluation\TraceEntry>  $trace
     *
     * @return \SineMacula\Laravel\Authorization\Evaluation\Decision|null
     */
    private function cap(array $statements, string $action, ?string $resource, CheckContext $context, array &$trace): ?Decision
    {
        $capped = $this->capBy(DecisionStage::GUARDRAIL, DecisionReason::GUARDRAIL, $statements['guardrails'], $action, $resource, $context, $trace);

        if ($capped === null) {
            $capped = $this->capBy(DecisionStage::BOUNDARY, DecisionReason::BOUNDARY, $statements['boundaries'], $action, $resource, $context, $trace);
        }

        if ($capped === null) {
            $trace[] = $this->passed(DecisionStage::SESSION, TraceOutcome::UNCAPPED);
        }

        return $capped;
    }

    /**
     * Run one cap stage, the guardrails' or the boundaries': every allow
     * statement of every cap is assessed, each cap in turn, and the check
     * passes only when each cap has one that allows it. Each cap that does not
     * adds a step naming it. Return the denial when one does not, with the
     * stage's reason, or as `invalid_policy` when a cap's statement cannot be
     * evaluated, or null when every cap allows it, there is none, or the caps
     * are null because the check is exempt from the stage.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage  $stage
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason  $reason
     * @param  list<array{list<StatementEntry>, \SineMacula\Laravel\Authorization\Evaluation\TraceEntry}>|null  $caps
     * @param  string  $action
     * @param  string|null  $resource
     * @param  \SineMacula\Laravel\Authorization\Evaluation\CheckContext  $context
     * @param  list<\SineMacula\Laravel\Authorization\Evaluation\TraceEntry>  $trace
     *
     * @param-out list<\SineMacula\Laravel\Authorization\Evaluation\TraceEntry>  $trace
     *
     * @return \SineMacula\Laravel\Authorization\Evaluation\Decision|null
     */
    private function capBy(DecisionStage $stage, DecisionReason $reason, ?array $caps, string $action, ?string $resource, CheckContext $context, array &$trace): ?Decision
    {
        if ($caps === null || $caps === []) {
            $trace[] = $this->passed($stage, $caps === null ? TraceOutcome::EXEMPT : TraceOutcome::UNCAPPED);

            return null;
        }

        $invalid = [];
        $refused = false;

        foreach ($caps as [$statements, $refusal]) {
            [$found] = $this->assess($statements, $stage, $action, $resource, $context, $trace);
            $invalid = [...$invalid, ...$found[self::INVALID]];

            if ($found[self::ALLOW] !== []) {
                continue;
            }

            // A cap that does not allow the check, one with no allow statement
            // included, is named in the trace, so the decision says which cap
            // refused it.
            $refused = true;
            $trace[] = $refusal;
        }

        return match (true) {
            $invalid !== [] => Decision::deny(DecisionReason::INVALID_POLICY, $stage, $invalid, $trace),
            $refused        => Decision::deny($reason, $stage, [], $trace),
            default         => null,
        };
    }

    /**
     * Run the allow stage, and conclude the decision: an allow statement that
     * matches allows, failing that a permission the subject holds, and failing
     * that the implicit deny decides. The permission is asked only when no
     * allow statement matched and none was invalid, and its step recorded.
     *
     * @param  list<StatementEntry>  $statements
     * @param  string  $action
     * @param  string|null  $resource
     * @param  \SineMacula\Laravel\Authorization\Evaluation\CheckContext  $context
     * @param  (\Closure(): bool)|null  $permission
     * @param  list<\SineMacula\Laravel\Authorization\Evaluation\TraceEntry>  $trace
     * @return \SineMacula\Laravel\Authorization\Evaluation\Decision
     */
    private function allow(array $statements, string $action, ?string $resource, CheckContext $context, ?\Closure $permission, array $trace): Decision
    {
        [$allows, $requirements] = $this->assess($statements, DecisionStage::ALLOW, $action, $resource, $context, $trace);

        if ($permission !== null && $allows[self::ALLOW] === [] && $allows[self::INVALID] === []) {
            $held    = $permission();
            $trace[] = new TraceEntry(DecisionStage::ALLOW, $held ? TraceOutcome::HELD : TraceOutcome::NOT_HELD);

            if ($held) {
                return Decision::allow(DecisionStage::ALLOW, [], $trace);
            }
        }

        return self::conclude(DecisionStage::ALLOW, $allows, $requirements, $trace);
    }

    /**
     * Assess the statements of one stage, adding each to the trace, and return
     * what they found, by how each bears on the check, with the unmet
     * requirement of each allow statement that only it kept from applying, in
     * the order of those statements.
     *
     * @param  list<StatementEntry>  $statements
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage  $stage
     * @param  string  $action
     * @param  string|null  $resource
     * @param  \SineMacula\Laravel\Authorization\Evaluation\CheckContext  $context
     * @param  list<\SineMacula\Laravel\Authorization\Evaluation\TraceEntry>  $trace
     *
     * @param-out list<\SineMacula\Laravel\Authorization\Evaluation\TraceEntry>  $trace
     *
     * @return array{array<string, list<\SineMacula\Laravel\Authorization\Evaluation\StatementReference>>, list<\SineMacula\Laravel\Authorization\Evaluation\UnmetRequirement>}
     */
    private function assess(array $statements, DecisionStage $stage, string $action, ?string $resource, CheckContext $context, array &$trace): array
    {
        $found        = [self::DENY => [], self::INVALID => [], self::ALLOW => [], self::INSUFFICIENT => [], self::FAILED => [], self::NONE => []];
        $requirements = [];
        $isDeny       = $stage === DecisionStage::DENY;

        foreach ($statements as [$reference, $statement, $notApplicable]) {
            // Most statements do not name the action, and decide nothing.
            if (!$statement->coversAction($action)) {
                $trace[] = $notApplicable;

                continue;
            }

            // An allow, a guardrail's or a boundary's included, applies only to
            // the subjects its source admits.
            if (!$isDeny && !self::isForSubject($reference, $statement, $context)) {
                $trace[] = new TraceEntry($stage, TraceOutcome::PRINCIPAL_MISMATCH, $reference);

                continue;
            }

            $assessment = $statement->assess($action, $resource, $context, $this->interpolator());
            $outcome    = self::outcomeOf($assessment);
            $unmet      = $stage === DecisionStage::ALLOW ? $assessment->unmetRequirement : null;

            $trace[] = new TraceEntry($stage, $outcome, $reference, $assessment->conditions ?? []);

            if ($unmet === null) {
                $found[self::categoryOf($isDeny, $outcome)][] = $reference;

                continue;
            }

            $found[self::INSUFFICIENT][] = $reference;
            $requirements[]              = $unmet;
        }

        return [$found, $requirements];
    }

    /**
     * Determine whether an allow statement applies to the check's subject, as
     * its source admits: in a resource policy, only when one of its
     * `principals` names the subject; in a policy attached any other way, a
     * guardrail or a boundary included, only when it names no principals.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\StatementReference  $reference
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Statement  $statement
     * @param  \SineMacula\Laravel\Authorization\Evaluation\CheckContext  $context
     * @return bool
     */
    private static function isForSubject(StatementReference $reference, Statement $statement, CheckContext $context): bool
    {
        if ($reference->resource === null) {
            return $statement->principals === null;
        }

        return $statement->principals !== null && $context->isSubjectNamedBy($statement->principals);
    }

    /**
     * Return what a statement's assessment found.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\MatchResult  $assessment
     * @return \SineMacula\Laravel\Authorization\Evaluation\Enums\TraceOutcome
     */
    private static function outcomeOf(MatchResult $assessment): TraceOutcome
    {
        return match ($assessment->outcome) {
            MatchOutcome::MATCHES        => TraceOutcome::MATCHED,
            MatchOutcome::UNDECIDABLE    => TraceOutcome::UNDECIDABLE,
            MatchOutcome::INVALID        => TraceOutcome::INVALID,
            MatchOutcome::DOES_NOT_MATCH => $assessment->conditions === null ? TraceOutcome::NOT_APPLICABLE : TraceOutcome::CONDITION_FAILED,
        };
    }

    /**
     * Return how a statement bears on the check: a deny when a deny statement
     * applies or cannot be decided, an allow when an allow statement matches, a
     * failed allow when one names the check but its conditions do not hold or
     * cannot be decided, and invalid when it cannot be evaluated.
     *
     * @param  bool  $isDeny
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\TraceOutcome  $outcome
     * @return string
     */
    private static function categoryOf(bool $isDeny, TraceOutcome $outcome): string
    {
        $bearing = match ($outcome) {
            TraceOutcome::INVALID        => self::INVALID,
            TraceOutcome::NOT_APPLICABLE => self::NONE,
            default                      => null,
        };

        if ($bearing !== null) {
            return $bearing;
        }

        if ($isDeny) {
            return $outcome === TraceOutcome::CONDITION_FAILED ? self::NONE : self::DENY;
        }

        return $outcome === TraceOutcome::MATCHED ? self::ALLOW : self::FAILED;
    }

    /**
     * Conclude the decision from what the deny or the allow stage's statements
     * found: an explicit deny, then an invalid statement, then an allow, then
     * an implicit deny: insufficient authentication, then a failed condition,
     * then no match. An invalid statement denies at the stage that found it.
     *
     * By the time the allow stage concludes, every deny and every cap has let
     * the check through, so insufficient authentication is only ever concluded
     * once nothing refuses it but the requirement.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage  $stage
     * @param  array<string, list<\SineMacula\Laravel\Authorization\Evaluation\StatementReference>>  $found
     * @param  list<\SineMacula\Laravel\Authorization\Evaluation\UnmetRequirement>  $requirements
     * @param  list<\SineMacula\Laravel\Authorization\Evaluation\TraceEntry>  $trace
     * @return \SineMacula\Laravel\Authorization\Evaluation\Decision
     */
    private static function conclude(DecisionStage $stage, array $found, array $requirements, array $trace): Decision
    {
        return match (true) {
            $found[self::DENY]         !== [] => Decision::deny(DecisionReason::EXPLICIT_DENY, DecisionStage::DENY, $found[self::DENY], $trace),
            $found[self::INVALID]      !== [] => Decision::deny(DecisionReason::INVALID_POLICY, $stage, $found[self::INVALID], $trace),
            $found[self::ALLOW]        !== [] => Decision::allow(DecisionStage::ALLOW, $found[self::ALLOW], $trace),
            $found[self::INSUFFICIENT] !== [] => Decision::insufficientAuthentication(DecisionStage::IMPLICIT, $found[self::INSUFFICIENT], $requirements, $trace),
            $found[self::FAILED]       !== [] => Decision::deny(DecisionReason::CONDITION_FAILED, DecisionStage::IMPLICIT, [], $trace),
            default                           => Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT, [], $trace),
        };
    }

    /**
     * Return the step a cap stage adds when it caps nothing, or when the check
     * is exempt from it, made once for each.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage  $stage
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\TraceOutcome  $outcome
     * @return \SineMacula\Laravel\Authorization\Evaluation\TraceEntry
     */
    private function passed(DecisionStage $stage, TraceOutcome $outcome): TraceEntry
    {
        return $this->passed[$stage->value . ':' . $outcome->value] ??= new TraceEntry($stage, $outcome);
    }

    /**
     * Return the interpolator, created on first use.
     *
     * @return \SineMacula\Laravel\Authorization\Evaluation\ContextInterpolator
     */
    private function interpolator(): ContextInterpolator
    {
        return $this->interpolator ??= new ContextInterpolator;
    }
}
