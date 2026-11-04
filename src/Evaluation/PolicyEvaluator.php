<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

use SineMacula\Laravel\Authorization\Evaluation\Enums\MatchOutcome;
use SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect;
use SineMacula\Laravel\Authorization\Evaluation\Enums\TraceDecision;

/**
 * AWS IAM-style policy evaluator.
 *
 * The evaluator walks every statement from every supplied policy in order,
 * building up a trace as it goes. Behaviour mirrors AWS IAM's four-step
 * decision order — implicit deny → explicit deny → allow → implicit deny — so
 * an explicit deny always wins, regardless of how many allows preceded it.
 *
 * The evaluator fails closed: a deny statement applies when its test cannot be
 * decided (a missing context key, an unresolved `${…}` reference), and a
 * malformed statement denies the check as an invalid policy, so no fault in a
 * statement ever skips a deny.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class PolicyEvaluator
{
    /** @var string A statement that allows the check. */
    private const string ALLOW = 'allow';

    /** @var string A statement that denies the check. */
    private const string DENY = 'deny';

    /** @var string A malformed statement; the check denies as an invalid policy. */
    private const string INVALID = 'invalid';

    /** @var string A statement that does not apply to the check. */
    private const string SKIP = 'skip';

    /** @var \SineMacula\Laravel\Authorization\Evaluation\ContextInterpolator|null */
    private ?ContextInterpolator $interpolator = null;

    /**
     * Evaluate the supplied policies against the action, resource and context.
     *
     * A deny statement whose test cannot be decided applies, an allow statement
     * whose test cannot be decided does not, and a malformed statement denies
     * the whole check as an invalid policy.
     *
     * @param  array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>  $policies
     * @param  string  $action
     * @param  string|null  $resource
     * @param  array<string, mixed>  $context
     * @param  object|null  $principal
     * @return \SineMacula\Laravel\Authorization\Evaluation\EvaluationResult
     */
    public function evaluate(array $policies, string $action, ?string $resource = null, array $context = [], ?object $principal = null): EvaluationResult
    {
        $interpolator = $this->interpolator();

        /** @var list<array{policy: string, statement_index: int, decision: \SineMacula\Laravel\Authorization\Evaluation\Enums\TraceDecision, reason: string}> $trace */
        $trace          = [];
        $allowStatement = null;

        foreach (self::statementsOf($policies) as [$policyName, $index, $statement]) {
            $assessment = $statement->assess($action, $resource, $context, $interpolator, $principal);
            $decision   = self::decide($statement, $assessment);
            $trace[]    = $this->traceEntry($policyName, $index, $decision, self::reason($decision, $assessment));

            if ($decision === self::INVALID || $decision === self::DENY) {
                return $decision === self::INVALID
                    ? EvaluationResult::invalidPolicy($trace)
                    : EvaluationResult::explicitlyDenied($statement, $trace);
            }

            $allowStatement ??= $decision === self::ALLOW ? $statement : null;
        }

        return $allowStatement !== null
            ? EvaluationResult::allowed($allowStatement, $trace)
            : EvaluationResult::implicitlyDenied($trace);
    }

    /**
     * Yield every statement of every policy, in order, with its policy's name
     * and its index within the policy.
     *
     * @param  array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>  $policies
     * @return \Generator<int, array{0: string, 1: int, 2: \SineMacula\Laravel\Authorization\Evaluation\Statement}>
     */
    private static function statementsOf(array $policies): \Generator
    {
        foreach ($policies as $policy) {
            foreach ($policy->statements as $index => $statement) {
                yield [$policy->name, $index, $statement];
            }
        }
    }

    /**
     * Decide what an assessed statement contributes to the check.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Statement  $statement
     * @param  \SineMacula\Laravel\Authorization\Evaluation\MatchResult  $assessment
     * @return string
     */
    private static function decide(Statement $statement, MatchResult $assessment): string
    {
        $deny = $statement->effect === PolicyEffect::DENY;

        return match ($assessment->outcome) {
            MatchOutcome::INVALID        => self::INVALID,
            MatchOutcome::MATCHES        => $deny ? self::DENY : self::ALLOW,
            MatchOutcome::UNDECIDABLE    => $deny ? self::DENY : self::SKIP,
            MatchOutcome::DOES_NOT_MATCH => self::SKIP,
        };
    }

    /**
     * Describe the decision for the trace.
     *
     * @param  string  $decision
     * @param  \SineMacula\Laravel\Authorization\Evaluation\MatchResult  $assessment
     * @return string
     */
    private static function reason(string $decision, MatchResult $assessment): string
    {
        $label = match ($decision) {
            self::INVALID => 'invalid statement',
            self::DENY    => 'explicit deny',
            self::ALLOW   => 'explicit allow',
            default       => $assessment->outcome === MatchOutcome::UNDECIDABLE ? 'could not be decided' : 'conditions not satisfied',
        };

        if ($assessment->outcome === MatchOutcome::DOES_NOT_MATCH) {
            return $assessment->detail !== '' ? $assessment->detail : $label;
        }

        return $assessment->detail !== '' ? "{$label}: {$assessment->detail}" : $label;
    }

    /**
     * Build the trace entry recorded for an assessed statement.
     *
     * @param  string  $policy
     * @param  int  $index
     * @param  string  $decision
     * @param  string  $reason
     * @return array{policy: string, statement_index: int, decision: \SineMacula\Laravel\Authorization\Evaluation\Enums\TraceDecision, reason: string}
     */
    private function traceEntry(string $policy, int $index, string $decision, string $reason): array
    {
        return [
            'policy'          => $policy,
            'statement_index' => $index,
            'decision'        => $decision === self::SKIP ? TraceDecision::SKIPPED : TraceDecision::MATCHED,
            'reason'          => $reason,
        ];
    }

    /**
     * Return the shared context interpolator instance.
     *
     * @return \SineMacula\Laravel\Authorization\Evaluation\ContextInterpolator
     */
    private function interpolator(): ContextInterpolator
    {
        return $this->interpolator ??= new ContextInterpolator;
    }
}
