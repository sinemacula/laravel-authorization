<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\Enums\TraceOutcome;

/**
 * One step of a decision: the stage it belongs to, what it found, the statement
 * it assessed (none for a permission, or for a cap stage that found nothing to
 * cap by), the guardrail or permission boundary it is about when it is about no
 * one statement, and the condition keys it tested with whether each held.
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
     * @param  string|null  $cap
     */
    public function __construct(

        /** The stage the step belongs to. */
        public DecisionStage $stage,

        /** What the step found. */
        public TraceOutcome $outcome,

        /** The statement assessed; null for a permission, or a cap stage that capped nothing. */
        public ?StatementReference $statement = null,

        /** Each condition key tested, with whether it held. */
        public array $conditions = [],

        /** The guardrail or permission boundary a step about no one statement is about, as `name[key]`, such as one that refused the check; null for none. */
        public ?string $cap = null,
    ) {}

    /**
     * Return the entry as one line of an explanation: the statement it
     * assessed, else the guardrail or boundary it is about, else what its stage
     * weighs, the permission at the allow stage and the caps at a cap stage.
     *
     * @return string
     */
    public function toString(): string
    {
        $subject = $this->statement?->toString() ?? $this->cap ?? match ($this->stage) {
            DecisionStage::GUARDRAIL => 'guardrails',
            DecisionStage::BOUNDARY  => 'boundaries',
            DecisionStage::SESSION   => 'session caps',
            default                  => 'permission',
        };

        $conditions = [];

        foreach ($this->conditions as $key => $holds) {
            $conditions[] = $key . ($holds ? ' held' : ' failed');
        }

        return "[{$this->stage->value}] {$subject}: {$this->outcome->value}" . ($conditions === [] ? '' : ' (' . \implode(', ', $conditions) . ')');
    }
}
