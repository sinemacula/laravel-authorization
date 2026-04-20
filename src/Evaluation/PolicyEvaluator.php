<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

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
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class PolicyEvaluator
{
    /** @var \SineMacula\Laravel\Authorization\Evaluation\ContextInterpolator|null */
    private ?ContextInterpolator $interpolator = null;

    /**
     * Evaluate the supplied policies against the action, resource and context.
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

        // @formatter:off
        /** @var list<array{policy: string, statement_index: int, decision: \SineMacula\Laravel\Authorization\Evaluation\Enums\TraceDecision, reason: string}> $trace */
        // @formatter:on
        $trace          = [];
        $allowStatement = null;

        foreach ($policies as $policy) {
            foreach ($policy->statements as $index => $statement) {
                $reason        = $this->classifyStatement($statement, $action, $resource, $context, $principal, $interpolator);
                $traceDecision = $reason === 'action/resource did not match' || $reason === 'conditions not satisfied'
                    ? TraceDecision::SKIPPED
                    : TraceDecision::MATCHED;

                $trace[] = [
                    'policy'          => $policy->name,
                    'statement_index' => $index,
                    'decision'        => $traceDecision,
                    'reason'          => $reason,
                ];

                if ($reason === 'explicit deny') {
                    return EvaluationResult::explicitlyDenied($statement, $trace);
                }

                if ($reason === 'explicit allow') {
                    $allowStatement ??= $statement;
                }
            }
        }

        return $allowStatement !== null
            ? EvaluationResult::allowed($allowStatement, $trace)
            : EvaluationResult::implicitlyDenied($trace);
    }

    /**
     * Classify a statement against the evaluation inputs into one of the four
     * trace reasons used by `evaluate()`.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Statement  $statement
     * @param  string  $action
     * @param  string|null  $resource
     * @param  array<string, mixed>  $context
     * @param  object|null  $principal
     * @param  \SineMacula\Laravel\Authorization\Evaluation\ContextInterpolator  $interpolator
     * @return string
     */
    private function classifyStatement(Statement $statement, string $action, ?string $resource, array $context, ?object $principal, ContextInterpolator $interpolator): string
    {
        if (!$statement->matches($action, $resource, $interpolator, $principal, $context)) {
            return 'action/resource did not match';
        }

        if (!$statement->evaluateConditions($context, $interpolator, $principal, $resource)) {
            return 'conditions not satisfied';
        }

        return $statement->effect === PolicyEffect::DENY ? 'explicit deny' : 'explicit allow';
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
