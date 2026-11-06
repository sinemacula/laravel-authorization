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
 * An `insufficient_authentication` denial (AUTHZ-7.8, N35) also carries the
 * requirements that alone kept an allow statement from applying, each with its
 * unmet parts: alternatives, any one of which met would allow the check. A
 * decision that read an authentication requirement carries how long it may be
 * reused (N37): never beyond the instant a met requirement stops being met, nor
 * in another session. It keeps that session only as a non-reversible
 * fingerprint, never the session id, so the decision stays safe to log or
 * store.
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
     * @param  list<\SineMacula\Laravel\Authorization\Evaluation\UnmetRequirement>  $requirements
     * @param  \SineMacula\Laravel\Authorization\Evaluation\RequirementFreshness|null  $freshness
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

        /** For insufficient authentication, each requirement that alone kept an allow from applying, with its unmet parts. */
        public array $requirements = [],

        /** How long the decision may be reused; null when it read no authentication requirement. */
        public ?RequirementFreshness $freshness = null,
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
     * Return an `insufficient_authentication` denial, decided at the stage by
     * the allow statements whose authentication requirements alone did not
     * hold, with each requirement and its unmet parts, in the same order.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage  $stage
     * @param  list<\SineMacula\Laravel\Authorization\Evaluation\StatementReference>  $statements
     * @param  list<\SineMacula\Laravel\Authorization\Evaluation\UnmetRequirement>  $requirements
     * @param  list<\SineMacula\Laravel\Authorization\Evaluation\TraceEntry>  $trace
     * @return self
     */
    public static function insufficientAuthentication(DecisionStage $stage, array $statements, array $requirements, array $trace = []): self
    {
        return new self(DecisionEffect::DENY, DecisionReason::INSUFFICIENT_AUTHENTICATION, $stage, $statements, $trace, $requirements);
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

        return $held
            ? new self(DecisionEffect::ALLOW, null, DecisionStage::ALLOW, [], [...$this->trace, $step], [], $this->freshness)
            : $this->withStep($step);
    }

    /**
     * Return the decision with one more step at the end of its trace.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\TraceEntry  $entry
     * @return self
     */
    public function withStep(TraceEntry $entry): self
    {
        return new self($this->effect, $this->reason, $this->stage, $this->statements, [...$this->trace, $entry], $this->requirements, $this->freshness);
    }

    /**
     * Return the decision with how long it may be reused, or itself when it
     * read no authentication requirement.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\RequirementFreshness|null  $freshness
     * @return self
     */
    public function withFreshness(?RequirementFreshness $freshness): self
    {
        if ($freshness === null) {
            return $this;
        }

        return new self($this->effect, $this->reason, $this->stage, $this->statements, $this->trace, $this->requirements, $freshness);
    }

    /**
     * Determine whether the decision may still be reused in the session at the
     * instant (now when none is given). A decision that read no requirement may
     * always be; one that did, only in the session it was made in and before
     * any met requirement it read stops being met.
     *
     * @param  string|null  $session
     * @param  \DateTimeInterface|null  $at
     * @return bool
     */
    public function isFreshFor(?string $session, ?\DateTimeInterface $at = null): bool
    {
        return $this->freshness?->holdsFor($session, $at) ?? true;
    }

    /**
     * Return the decision as text: the verdict, the stage and the statements
     * that decided it, each requirement an insufficient authentication names
     * with its unmet parts, then each step of the trace.
     *
     * @return string
     */
    public function explain(): string
    {
        $verdict    = $this->isAllowed() ? 'ALLOW' : "DENY ({$this->reason?->value}: {$this->reason?->label()})";
        $statements = \implode(', ', \array_map(static fn (StatementReference $statement): string => $statement->toString(), $this->statements));
        $lines      = ["{$verdict} at the {$this->stage->value} stage" . ($statements === '' ? '.' : " by {$statements}.")];

        foreach ($this->requirements as $requirement) {
            $lines[] = '  requirement ' . \implode(', ', $requirement->requirement->names()) . ': unmet ' . \implode(', ', $requirement->unmet);
        }

        foreach ($this->trace as $entry) {
            $lines[] = '  ' . $entry->toString();
        }

        return \implode("\n", $lines);
    }
}
