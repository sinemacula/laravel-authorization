<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect;
use SineMacula\Laravel\Authorization\Evaluation\Enums\TraceOutcome;

/**
 * The statements a decision assesses, gathered from its policies and its
 * permission boundaries in the fixed order every decision keeps (AUTHZ-7.9).
 *
 * The policies are ordered by name, then stored key, then the resource a
 * resource policy is attached to, then document, and each statement by its
 * position, so the statements come out the same whatever order the policies
 * were read in. A boundary's deny statements join the deny stage after every
 * policy's, and its allow statements are kept apart, one list per boundary, for
 * the boundary stage, the boundaries in the same order.
 *
 * What a policy gives is worked out once, while the policy lives: its deny and
 * allow statements apart, each with its reference and the trace entry it adds
 * when it does not name the action, and what it is ordered by; and, once it is
 * read as a boundary, its allow statements with the boundary stage's entries.
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
 *     boundaries: list<list<array{
 *         \SineMacula\Laravel\Authorization\Evaluation\StatementReference,
 *         \SineMacula\Laravel\Authorization\Evaluation\Statement,
 *         \SineMacula\Laravel\Authorization\Evaluation\TraceEntry
 *     }>>
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
     * Each boundary's allow statements with the boundary stage's trace entries,
     * kept while the policy lives.
     *
     * @var \WeakMap<\SineMacula\Laravel\Authorization\Evaluation\Policy, list<StatementEntry>>|null
     */
    private ?\WeakMap $boundaries = null;

    /**
     * Return the statements of the policies and the boundaries, in order: every
     * deny statement, the policies' and then the boundaries', every allow
     * statement of the policies, and each boundary's allow statements.
     *
     * @param  array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>  $policies
     * @param  array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>  $boundaries
     * @return Gathered
     */
    public function of(array $policies, array $boundaries = []): array
    {
        $denies = [];
        $allows = [];
        $bounds = [];

        foreach ($this->sorted($policies) as [$entries]) {
            $denies[] = $entries['deny'];
            $allows[] = $entries['allow'];
        }

        foreach ($this->sorted($boundaries) as [$entries, $boundary]) {
            $denies[] = $entries['deny'];
            $bounds[] = $this->boundaryEntriesOf($boundary, $entries['allow']);
        }

        return ['deny' => \array_merge(...$denies), 'allow' => \array_merge(...$allows), 'boundaries' => $bounds];
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
     * Return a boundary's allow statements with the trace entry each adds at
     * the boundary stage when it does not name the action, worked out once per
     * policy.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Policy  $boundary
     * @param  list<StatementEntry>  $allows
     * @return list<StatementEntry>
     */
    private function boundaryEntriesOf(Policy $boundary, array $allows): array
    {
        $this->boundaries ??= new \WeakMap;

        if (!isset($this->boundaries[$boundary])) {
            $entries = [];

            foreach ($allows as [$reference, $statement]) {
                $entries[] = [$reference, $statement, new TraceEntry(DecisionStage::BOUNDARY, TraceOutcome::NOT_APPLICABLE, $reference)];
            }

            $this->boundaries[$boundary] = $entries;
        }

        return $this->boundaries[$boundary];
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
