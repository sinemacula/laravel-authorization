<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect;
use SineMacula\Laravel\Authorization\Evaluation\Enums\TraceOutcome;

/**
 * The statements a decision assesses, gathered from its policies, its
 * guardrails and its permission boundaries in the fixed order every decision
 * keeps (AUTHZ-7.9).
 *
 * The policies are ordered by name, then stored key, then the resource a
 * resource policy is attached to, then document, and each statement by its
 * position, so the statements come out the same whatever order the policies
 * were read in. A guardrail's and a boundary's deny statements join the deny
 * stage after every policy's, the guardrails' first, and their allow statements
 * are kept apart, one list per guardrail for the guardrail stage and one per
 * boundary for the boundary stage, each in the same order, each with the step
 * it adds when it refuses the check.
 *
 * A policy reached more than once, such as one held by both the principal and
 * its identity, one held and set as a guardrail or a boundary too, or one that
 * is the boundary of both, is gathered once for each part it plays: its deny
 * statements once, its allow statements once as a policy, once as a guardrail
 * and once as a boundary. Two policies that tie on what they are ordered by are
 * the same policy, attached the same way, and intersecting a cap with itself
 * changes nothing, so the decision is unchanged and names each statement once.
 *
 * What a policy gives is worked out once, while the policy lives: its deny and
 * allow statements apart, each with its reference and the trace entry it adds
 * when it does not name the action, and what it is ordered by; and, once it is
 * read as a guardrail or a boundary, its allow statements with that stage's
 * entries and the step it adds when it refuses the check.
 *
 * @phpstan-type StatementEntry array{
 *     \SineMacula\Laravel\Authorization\Evaluation\StatementReference,
 *     \SineMacula\Laravel\Authorization\Evaluation\Statement,
 *     \SineMacula\Laravel\Authorization\Evaluation\TraceEntry
 * }
 * @phpstan-type PolicyEntries array{
 *     order: string,
 *     deny: list<array{
 *         \SineMacula\Laravel\Authorization\Evaluation\StatementReference,
 *         \SineMacula\Laravel\Authorization\Evaluation\Statement,
 *         \SineMacula\Laravel\Authorization\Evaluation\TraceEntry
 *     }>,
 *     allow: list<array{
 *         \SineMacula\Laravel\Authorization\Evaluation\StatementReference,
 *         \SineMacula\Laravel\Authorization\Evaluation\Statement,
 *         \SineMacula\Laravel\Authorization\Evaluation\TraceEntry
 *     }>
 * }
 * @phpstan-type Gathered array{
 *     deny: list<array{
 *         \SineMacula\Laravel\Authorization\Evaluation\StatementReference,
 *         \SineMacula\Laravel\Authorization\Evaluation\Statement,
 *         \SineMacula\Laravel\Authorization\Evaluation\TraceEntry
 *     }>,
 *     allow: list<array{
 *         \SineMacula\Laravel\Authorization\Evaluation\StatementReference,
 *         \SineMacula\Laravel\Authorization\Evaluation\Statement,
 *         \SineMacula\Laravel\Authorization\Evaluation\TraceEntry
 *     }>,
 *     guardrails: list<array{
 *         list<array{
 *             \SineMacula\Laravel\Authorization\Evaluation\StatementReference,
 *             \SineMacula\Laravel\Authorization\Evaluation\Statement,
 *             \SineMacula\Laravel\Authorization\Evaluation\TraceEntry
 *         }>,
 *         \SineMacula\Laravel\Authorization\Evaluation\TraceEntry
 *     }>,
 *     boundaries: list<array{
 *         list<array{
 *             \SineMacula\Laravel\Authorization\Evaluation\StatementReference,
 *             \SineMacula\Laravel\Authorization\Evaluation\Statement,
 *             \SineMacula\Laravel\Authorization\Evaluation\TraceEntry
 *         }>,
 *         \SineMacula\Laravel\Authorization\Evaluation\TraceEntry
 *     }>
 * }
 * @phpstan-type CapEntries array{
 *     list<array{
 *         \SineMacula\Laravel\Authorization\Evaluation\StatementReference,
 *         \SineMacula\Laravel\Authorization\Evaluation\Statement,
 *         \SineMacula\Laravel\Authorization\Evaluation\TraceEntry
 *     }>,
 *     \SineMacula\Laravel\Authorization\Evaluation\TraceEntry
 * }
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class StatementEntries
{
    /**
     * Each policy's statements with their references, and what it is ordered
     * by, kept while the policy lives.
     *
     * @var \WeakMap<\SineMacula\Laravel\Authorization\Evaluation\Policy, PolicyEntries>|null
     */
    private ?\WeakMap $policies = null;

    /**
     * Each guardrail's allow statements with the guardrail stage's trace
     * entries, and the step it adds when it refuses the check, kept while the
     * policy lives.
     *
     * @var \WeakMap<\SineMacula\Laravel\Authorization\Evaluation\Policy, CapEntries>|null
     */
    private ?\WeakMap $guardrails = null;

    /**
     * Each boundary's allow statements with the boundary stage's trace entries,
     * and the step it adds when it refuses the check, kept while the policy
     * lives.
     *
     * @var \WeakMap<\SineMacula\Laravel\Authorization\Evaluation\Policy, CapEntries>|null
     */
    private ?\WeakMap $boundaries = null;

    /**
     * Return the statements of the policies, the guardrails and the boundaries,
     * in order: every deny statement, the policies', then the guardrails', then
     * the boundaries', every allow statement of the policies, each guardrail's
     * allow statements and each boundary's, each policy gathered once for each
     * part it plays.
     *
     * @param  array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>  $policies
     * @param  array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>  $boundaries
     * @param  array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>  $guardrails
     * @return Gathered
     */
    public function of(array $policies, array $boundaries = [], array $guardrails = []): array
    {
        $denies = [];
        $allows = [];
        $caps   = [DecisionStage::GUARDRAIL->value => [], DecisionStage::BOUNDARY->value => []];

        foreach ($this->sorted($policies) as [$entries]) {
            $denies[$entries['order']] ??= $entries['deny'];
            $allows[$entries['order']] ??= $entries['allow'];
        }

        foreach ([[DecisionStage::GUARDRAIL, $guardrails], [DecisionStage::BOUNDARY, $boundaries]] as [$stage, $capping]) {
            foreach ($this->sorted($capping) as [$entries, $cap]) {
                $denies[$entries['order']]              ??= $entries['deny'];
                $caps[$stage->value][$entries['order']] ??= $this->capEntriesOf($stage, $cap, $entries['allow']);
            }
        }

        return [
            'deny'       => \array_merge(...\array_values($denies)),
            'allow'      => \array_merge(...\array_values($allows)),
            'guardrails' => \array_values($caps[DecisionStage::GUARDRAIL->value]),
            'boundaries' => \array_values($caps[DecisionStage::BOUNDARY->value]),
        ];
    }

    /**
     * Return each policy with what it gives, in order of what it is ordered by.
     *
     * @param  array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>  $policies
     * @return list<array{PolicyEntries, \SineMacula\Laravel\Authorization\Evaluation\Policy}>
     */
    private function sorted(array $policies): array
    {
        $sorted = [];

        foreach ($policies as $policy) {
            $sorted[] = [$this->entriesOf($policy), $policy];
        }

        \usort($sorted, static fn (array $left, array $right): int => \strcmp($left[0]['order'], $right[0]['order']));

        return $sorted;
    }

    /**
     * Return a policy's statements, each with its reference and the trace entry
     * it adds when it does not name the action, the deny statements and the
     * allow statements apart, and what the policy is ordered by, worked out
     * once per policy.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Policy  $policy
     * @return PolicyEntries
     */
    private function entriesOf(Policy $policy): array
    {
        $this->policies ??= new \WeakMap;

        if (!isset($this->policies[$policy])) {
            $entries = ['order' => self::orderOf($policy), 'deny' => [], 'allow' => []];

            foreach ($policy->statements as $index => $statement) {
                $isDeny    = $statement->effect === PolicyEffect::DENY;
                $reference = new StatementReference($policy->name, $index, $policy->id, $statement->sid, $policy->resource);
                $stage     = $isDeny ? DecisionStage::DENY : DecisionStage::ALLOW;

                $entries[$isDeny ? 'deny' : 'allow'][] = [$reference, $statement, new TraceEntry($stage, TraceOutcome::NOT_APPLICABLE, $reference)];
            }

            $this->policies[$policy] = $entries;
        }

        return $this->policies[$policy];
    }

    /**
     * Return a guardrail's or a boundary's allow statements with the trace
     * entry each adds at its cap stage when it does not name the action, and
     * the step the cap adds when it refuses the check, naming it as
     * `name[key]`, worked out once per policy and stage.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage  $stage
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Policy  $cap
     * @param  list<StatementEntry>  $allows
     * @return CapEntries
     */
    private function capEntriesOf(DecisionStage $stage, Policy $cap, array $allows): array
    {
        $caps = $stage === DecisionStage::GUARDRAIL ? $this->guardrails ??= new \WeakMap : $this->boundaries ??= new \WeakMap;

        if (!isset($caps[$cap])) {
            $entries = [];

            foreach ($allows as [$reference, $statement]) {
                $entries[] = [$reference, $statement, new TraceEntry($stage, TraceOutcome::NOT_APPLICABLE, $reference)];
            }

            $name = $cap->name . ($cap->id === null ? '' : "[{$cap->id}]");

            $caps[$cap] = [$entries, new TraceEntry($stage, TraceOutcome::REFUSED, null, [], $name)];
        }

        return $caps[$cap];
    }

    /**
     * Return what a policy is ordered by: its name, then its stored key, then
     * the resource it is attached to, then its document, so policies of one
     * name take a fixed order too and two that tie on all four are the same
     * policy, attached the same way.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Policy  $policy
     * @return string
     */
    private static function orderOf(Policy $policy): string
    {
        return $policy->name . "\0" . ($policy->id ?? '') . "\0" . ($policy->resource ?? '') . "\0" . \json_encode($policy->toArray(), \JSON_THROW_ON_ERROR);
    }
}
