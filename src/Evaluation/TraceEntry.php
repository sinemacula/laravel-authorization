<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\Enums\TraceOutcome;

/**
 * One step of a decision: the stage it belongs to, what it found, the statement
 * it assessed (none for a permission), and the condition keys it tested with
 * whether each held.
 *
 * Never a value: only key names and results reach the trace (AUTHZ-8.8).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class TraceEntry
{
    /**
     * Create a new trace entry.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage  $stage
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\TraceOutcome  $outcome
     * @param  \SineMacula\Laravel\Authorization\Evaluation\StatementReference|null  $statement
     * @param  array<string, bool>  $conditions
     */
    public function __construct(

        /** The stage the step belongs to. */
        public DecisionStage $stage,

        /** What the step found. */
        public TraceOutcome $outcome,

        /** The statement assessed; null for a permission. */
        public ?StatementReference $statement = null,

        /** Each condition key tested, with whether it held. */
        public array $conditions = [],
    ) {}

    /**
     * Return the entry as one line of an explanation.
     *
     * @return string
     */
    public function toString(): string
    {
        $subject    = $this->statement?->toString() ?? 'permission';
        $conditions = [];

        foreach ($this->conditions as $key => $holds) {
            $conditions[] = $key . ($holds ? ' held' : ' failed');
        }

        return "[{$this->stage->value}] {$subject}: {$this->outcome->value}" . ($conditions === [] ? '' : ' (' . \implode(', ', $conditions) . ')');
    }
}
