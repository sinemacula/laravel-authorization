<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Permissions\Evaluation;

use SineMacula\Laravel\Iam\Permissions\Enums\PolicyEffect;

/**
 * Policy evaluator.
 *
 * Evaluates a set of IAM-style policies against a given action,
 * resource, and context. Follows AWS IAM evaluation logic:
 *
 * 1. Start with an implicit DENY
 * 2. Evaluate all applicable policy statements
 * 3. If any matching statement has an explicit DENY, return DENY
 * 4. If any matching statement has an ALLOW, return ALLOW
 * 5. Otherwise, return implicit DENY
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
final class PolicyEvaluator
{
    /**
     * Evaluate the given policies for the specified action and
     * resource.
     *
     * @param  array<int, \SineMacula\Laravel\Iam\Permissions\Evaluation\Policy>  $policies
     * @param  string  $action
     * @param  string|null  $resource
     * @param  array<string, mixed>  $context
     * @return \SineMacula\Laravel\Iam\Permissions\Evaluation\EvaluationResult
     */
    public function evaluate(array $policies, string $action, ?string $resource = null, array $context = []): EvaluationResult
    {
        $allowStatement = null;

        foreach ($policies as $policy) {
            foreach ($policy->statements as $statement) {
                if (!$statement->matches($action, $resource)) {
                    continue;
                }

                if (!$statement->evaluateConditions($context)) {
                    continue;
                }

                if ($statement->effect === PolicyEffect::DENY) {
                    return EvaluationResult::explicitlyDenied($statement);
                }

                $allowStatement ??= $statement;
            }
        }

        if ($allowStatement !== null) {
            return EvaluationResult::allowed($allowStatement);
        }

        return EvaluationResult::implicitlyDenied();
    }
}
