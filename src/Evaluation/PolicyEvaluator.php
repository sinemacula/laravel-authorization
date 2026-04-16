<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

use SineMacula\Laravel\Authorization\Enums\PolicyEffect;
use SineMacula\Laravel\Authorization\Enums\TraceDecision;

/**
 * AWS IAM-style policy evaluator.
 *
 * The evaluator walks every statement from every supplied policy in
 * order, building up a trace as it goes. Behaviour mirrors AWS IAM's
 * four-step decision order — implicit deny → explicit deny → allow →
 * implicit deny — so an explicit deny always wins, regardless of how
 * many allows preceded it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class PolicyEvaluator
{
    /** @var \SineMacula\Laravel\Authorization\Evaluation\ContextInterpolator|null Shared interpolator instance, created lazily. */
    private ?ContextInterpolator $interpolator = null;

    /**
     * Evaluate the supplied policies against the action, resource and
     * context.
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

        /** @var list<array{policy: string, statement_index: int, decision: \SineMacula\Laravel\Authorization\Enums\TraceDecision, reason: string}> $trace */
        $trace          = [];
        $allowStatement = null;

        foreach ($policies as $policy) {
            foreach ($policy->statements as $index => $statement) {
                if (!$statement->matches($action, $resource, $interpolator, $principal, $context)) {
                    $trace[] = [
                        'policy'          => $policy->name,
                        'statement_index' => $index,
                        'decision'        => TraceDecision::SKIPPED,
                        'reason'          => 'action/resource did not match',
                    ];

                    continue;
                }

                if (!$statement->evaluateConditions($context, $interpolator, $principal, $resource)) {
                    $trace[] = [
                        'policy'          => $policy->name,
                        'statement_index' => $index,
                        'decision'        => TraceDecision::SKIPPED,
                        'reason'          => 'conditions not satisfied',
                    ];

                    continue;
                }

                if ($statement->effect === PolicyEffect::DENY) {
                    $trace[] = [
                        'policy'          => $policy->name,
                        'statement_index' => $index,
                        'decision'        => TraceDecision::MATCHED,
                        'reason'          => 'explicit deny',
                    ];

                    return EvaluationResult::explicitlyDenied($statement, $trace);
                }

                $trace[] = [
                    'policy'          => $policy->name,
                    'statement_index' => $index,
                    'decision'        => TraceDecision::MATCHED,
                    'reason'          => 'explicit allow',
                ];

                $allowStatement ??= $statement;
            }
        }

        if ($allowStatement !== null) {
            return EvaluationResult::allowed($allowStatement, $trace);
        }

        return EvaluationResult::implicitlyDenied($trace);
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
