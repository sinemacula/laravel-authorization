<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionEffect;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\Enums\TraceOutcome;

/**
 * The decision of one check (AUTHZ-7.1, AUTHZ-7.9, AUTHZ-7.10, D11).
 *
 * It says whether the check is allowed, and, when it is denied, why, as a
 * machine-readable reason. It names the stage that decided it and the
 * statements that did (none for a permission held, or a denial no statement
 * made), and carries the trace of every step the decision took, in a fixed
 * order whatever order the policies were read in. The trace holds key names and
 * results, never a context or attribute value (AUTHZ-8.8), so it is safe to log
 * or store.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Decision
{
    /**
     * Create a new decision.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionEffect  $effect
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null  $reason
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage  $stage
     * @param  list<\SineMacula\Laravel\Authorization\Evaluation\StatementReference>  $statements
     * @param  list<\SineMacula\Laravel\Authorization\Evaluation\TraceEntry>  $trace
     */
    private function __construct(

        /** Whether the check is allowed or denied. */
        public DecisionEffect $effect,

        /** Why the check is denied; null when it is allowed. */
        public ?DecisionReason $reason,

        /** The stage that decided it. */
        public DecisionStage $stage,

        /** The statements that decided it, in the order they were assessed. */
        public array $statements = [],

        /** Every step the decision took, in order. */
        public array $trace = [],
    ) {}

    /**
     * Return an allow, decided at the stage by the statements.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage  $stage
     * @param  list<\SineMacula\Laravel\Authorization\Evaluation\StatementReference>  $statements
     * @param  list<\SineMacula\Laravel\Authorization\Evaluation\TraceEntry>  $trace
     * @return self
     */
    public static function allow(DecisionStage $stage, array $statements = [], array $trace = []): self
    {
        return new self(DecisionEffect::ALLOW, null, $stage, $statements, $trace);
    }

    /**
     * Return a denial for the reason, decided at the stage by the statements.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason  $reason
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage  $stage
     * @param  list<\SineMacula\Laravel\Authorization\Evaluation\StatementReference>  $statements
     * @param  list<\SineMacula\Laravel\Authorization\Evaluation\TraceEntry>  $trace
     * @return self
     */
    public static function deny(DecisionReason $reason, DecisionStage $stage, array $statements = [], array $trace = []): self
    {
        return new self(DecisionEffect::DENY, $reason, $stage, $statements, $trace);
    }

    /**
     * Determine whether the check is allowed.
     *
     * @return bool
     */
    public function isAllowed(): bool
    {
        return $this->effect === DecisionEffect::ALLOW;
    }

    /**
     * Return the decision once the subject's permissions are consulted, when no
     * statement decided it: an allow when the subject holds the permission the
     * action names, else the same denial, the step recorded either way.
     *
     * @param  bool  $held
     * @return self
     */
    public function withPermission(bool $held): self
    {
        $step = new TraceEntry(DecisionStage::ALLOW, $held ? TraceOutcome::HELD : TraceOutcome::NOT_HELD);

        return $held ? self::allow(DecisionStage::ALLOW, [], [...$this->trace, $step]) : $this->withStep($step);
    }

    /**
     * Return the decision with one more step at the end of its trace.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\TraceEntry  $entry
     * @return self
     */
    public function withStep(TraceEntry $entry): self
    {
        return new self($this->effect, $this->reason, $this->stage, $this->statements, [...$this->trace, $entry]);
    }

    /**
     * Return the decision as text: the verdict, the stage and the statements
     * that decided it, then each step of the trace.
     *
     * @return string
     */
    public function explain(): string
    {
        $verdict    = $this->isAllowed() ? 'ALLOW' : "DENY ({$this->reason?->value}: {$this->reason?->label()})";
        $statements = \implode(', ', \array_map(static fn (StatementReference $statement): string => $statement->toString(), $this->statements));
        $lines      = ["{$verdict} at the {$this->stage->value} stage" . ($statements === '' ? '.' : " by {$statements}.")];

        foreach ($this->trace as $entry) {
            $lines[] = '  ' . $entry->toString();
        }

        return \implode("\n", $lines);
    }
}
