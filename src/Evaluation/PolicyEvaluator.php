<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome;
use SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect;
use SineMacula\Laravel\Authorization\Evaluation\Enums\TraceOutcome;

/**
 * Decides a check from policy statements: the deny stage, then the allow stage,
 * then the implicit deny (AUTHZ-7.1).
 *
 * Every deny statement of every policy is assessed, then, when none decided,
 * every allow statement, each in a fixed order (the policies by name, each
 * statement by its position) and recorded in the trace, so the decision, its
 * trace and the statements that decided it are the same whatever order the
 * policies were read in (AUTHZ-7.9). An explicit deny wins over any allow, and
 * the allows are not assessed once a deny decided (N4). The evaluator fails
 * closed: a deny statement applies when its test cannot be decided (a missing
 * context key, an unresolved `${…}` reference), and a statement that cannot be
 * evaluated denies the check as an invalid policy, so no fault in a statement
 * ever skips a deny.
 *
 * Nothing allowed by a statement is denied as `condition_failed` when an allow
 * statement names the action and the resource but its conditions do not hold,
 * and as `no_match` otherwise. A permission the subject holds is a further
 * allow source, which the manager consults when the statements allow nothing.
 *
 * @phpstan-type StatementEntry array{\SineMacula\Laravel\Authorization\Evaluation\StatementReference, \SineMacula\Laravel\Authorization\Evaluation\Statement}
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

    /** @var string A statement that does not bear on the check. */
    private const string NONE = 'none';

    /** @var \SineMacula\Laravel\Authorization\Evaluation\ContextInterpolator|null Lazily created interpolator. */
    private ?ContextInterpolator $interpolator = null;

    /**
     * Decide the check from the policies' statements.
     *
     * @param  array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>  $policies
     * @param  string  $action
     * @param  string|null  $resource
     * @param  array<string, mixed>  $context
     * @param  object|null  $principal
     * @return \SineMacula\Laravel\Authorization\Evaluation\Decision
     */
    public function evaluate(array $policies, string $action, ?string $resource = null, array $context = [], ?object $principal = null): Decision
    {
        $statements = self::statementsOf($policies);
        $trace      = [];
        $denies     = $this->assess($statements[self::DENY], DecisionStage::DENY, $action, $resource, $context, $principal, $trace);

        if ($denies[self::DENY] !== [] || $denies[self::INVALID] !== []) {
            return self::conclude(DecisionStage::DENY, $denies, $trace);
        }

        $allows = $this->assess($statements[self::ALLOW], DecisionStage::ALLOW, $action, $resource, $context, $principal, $trace);

        return self::conclude(DecisionStage::ALLOW, $allows, $trace);
    }

    /**
     * Assess the statements of one stage, adding each to the trace, and return
     * what they found, by how each bears on the check.
     *
     * @param  list<StatementEntry>  $statements
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage  $stage
     * @param  string  $action
     * @param  string|null  $resource
     * @param  array<string, mixed>  $context
     * @param  object|null  $principal
     * @param  list<\SineMacula\Laravel\Authorization\Evaluation\TraceEntry>  $trace
     *
     * @param-out list<\SineMacula\Laravel\Authorization\Evaluation\TraceEntry>  $trace
     *
     * @return array<string, list<\SineMacula\Laravel\Authorization\Evaluation\StatementReference>>
     */
    private function assess(array $statements, DecisionStage $stage, string $action, ?string $resource, array $context, ?object $principal, array &$trace): array
    {
        $found = [self::DENY => [], self::INVALID => [], self::ALLOW => [], self::FAILED => [], self::NONE => []];

        foreach ($statements as [$reference, $statement]) {
            $assessment = $statement->assess($action, $resource, $context, $this->interpolator(), $principal);
            $outcome    = self::outcomeOf($assessment);

            $trace[]                                                             = new TraceEntry($stage, $outcome, $reference, $assessment->conditions ?? []);
            $found[self::categoryOf($stage === DecisionStage::DENY, $outcome)][] = $reference;
        }

        return $found;
    }

    /**
     * Return every statement of the policies with its reference, the deny
     * statements and the allow statements apart, the policies in order of name
     * and each statement in order of position.
     *
     * @param  array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>  $policies
     * @return array{deny: list<StatementEntry>, allow: list<StatementEntry>}
     */
    private static function statementsOf(array $policies): array
    {
        \usort($policies, static fn (Policy $left, Policy $right): int => \strcmp($left->name, $right->name));

        $statements = [self::DENY => [], self::ALLOW => []];

        foreach ($policies as $policy) {
            foreach ($policy->statements as $index => $statement) {
                $statements[$statement->effect === PolicyEffect::DENY ? self::DENY : self::ALLOW][] = [new StatementReference($policy->name, $index), $statement];
            }
        }

        return $statements;
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
     * Conclude the decision from what a stage's statements found: an explicit
     * deny, then an invalid statement, then an allow, then an implicit deny. An
     * invalid statement denies at the stage that found it.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage  $stage
     * @param  array<string, list<\SineMacula\Laravel\Authorization\Evaluation\StatementReference>>  $found
     * @param  list<\SineMacula\Laravel\Authorization\Evaluation\TraceEntry>  $trace
     * @return \SineMacula\Laravel\Authorization\Evaluation\Decision
     */
    private static function conclude(DecisionStage $stage, array $found, array $trace): Decision
    {
        return match (true) {
            $found[self::DENY]    !== [] => Decision::deny(DecisionReason::EXPLICIT_DENY, DecisionStage::DENY, $found[self::DENY], $trace),
            $found[self::INVALID] !== [] => Decision::deny(DecisionReason::INVALID_POLICY, $stage, $found[self::INVALID], $trace),
            $found[self::ALLOW]   !== [] => Decision::allow(DecisionStage::ALLOW, $found[self::ALLOW], $trace),
            $found[self::FAILED]  !== [] => Decision::deny(DecisionReason::CONDITION_FAILED, DecisionStage::IMPLICIT, [], $trace),
            default                      => Decision::deny(DecisionReason::NO_MATCH, DecisionStage::IMPLICIT, [], $trace),
        };
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
