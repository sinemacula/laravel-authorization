<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionEffect;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;

/**
 * The decision of one check (AUTHZ-7.1, AUTHZ-7.9, AUTHZ-7.10, D11).
 *
 * It says whether the check is allowed, and, when it is denied, why, as a
 * machine-readable reason. It names the stage that decided it and the
 * statements that did (none for a permission held, a boundary that does not
 * allow it, or another denial no statement made), and carries the trace of
 * every step the decision took, every stage it reached included, in a fixed
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
 * store. It also names every authentication requirement it read, by the names
 * of its parts, whether on a statement that allowed or one that denied, or in a
 * further check made for it, and whether met or not: what could change its
 * answer were the session's authentication state another, and none for a
 * decision no requirement could change (see `HeldPermission`).
 *
 * A decision made in explain mode (N89), as `Authorization::explain()` makes
 * it, also carries its evidence: where each grant that allowed it came from,
 * what the check asked, and, on its trace, each condition test with what it
 * found (see `DecisionEvidence`). Any other decision carries none, and
 * `explain()` explains it with what it has, marking the rest as not recorded,
 * never evaluating anything again.
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
     * @param  \SineMacula\Laravel\Authorization\Evaluation\DecisionEvidence|null  $evidence
     * @param  list<string>  $requirementsRead
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

        /** The evidence an explained check recorded; null for a decision made without explain mode. */
        public ?DecisionEvidence $evidence = null,

        /** The name of each part of every authentication requirement the decision read, allow or deny, met or not, once each, sorted; none when it read none. */
        public array $requirementsRead = [],
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
     * Determine whether the decision carries the evidence of an explained
     * check.
     *
     * @return bool
     */
    public function hasEvidence(): bool
    {
        return $this->evidence !== null;
    }

    /**
     * Return the name of each context key the decision depended on: every
     * condition key a step of its trace tested, whether or not its test held,
     * and every `${…}` reference a statement it assessed names, each once, in
     * the order first met. Names alone, never a value (AUTHZ-15.4).
     *
     * @return list<string>
     */
    public function keys(): array
    {
        $keys = [];

        foreach ($this->trace as $entry) {
            $keys = [...$keys, ...\array_map(\strval(...), \array_keys($entry->conditions)), ...$entry->dependencies];
        }

        return \array_values(\array_unique($keys));
    }

    /**
     * Return the decision with one more step at the end of its trace.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\TraceEntry  $entry
     * @return self
     */
    public function withStep(TraceEntry $entry): self
    {
        $trace = [...$this->trace, $entry];

        return new self($this->effect, $this->reason, $this->stage, $this->statements, $trace, $this->requirements, $this->freshness, $this->evidence, $this->requirementsRead);
    }

    /**
     * Return the decision with how long it may be reused and the name of each
     * part of every authentication requirement it read, or itself when neither
     * it nor what is given read a requirement. What is given adds to what the
     * decision already carries, as a further check made for it in the same
     * session does: it may be reused only until the earlier instant either
     * stops being met, and names every requirement either read, once each,
     * sorted.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\RequirementFreshness|null  $freshness
     * @param  list<string>  $requirementsRead
     * @return self
     */
    public function withFreshness(?RequirementFreshness $freshness, array $requirementsRead = []): self
    {
        $stricter = RequirementFreshness::stricterOf($this->freshness, $freshness);

        if ($stricter === null) {
            return $this;
        }

        $read = \array_unique([...$this->requirementsRead, ...$requirementsRead]);

        \sort($read, \SORT_STRING);

        return new self($this->effect, $this->reason, $this->stage, $this->statements, $this->trace, $this->requirements, $stricter, $this->evidence, $read);
    }

    /**
     * Return the decision with the evidence its explained check recorded.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\DecisionEvidence  $evidence
     * @return self
     */
    public function withEvidence(DecisionEvidence $evidence): self
    {
        return new self($this->effect, $this->reason, $this->stage, $this->statements, $this->trace, $this->requirements, $this->freshness, $evidence, $this->requirementsRead);
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
     * Return the decision's explanation (AUTHZ-11.5): the verdict, what decided
     * it, the evidence of every stage it reached and the stages it never
     * reached, from what the decision carries alone (see `Explanation`). A
     * decision made without explain mode explains with the evidence it has, the
     * rest marked as not recorded. Nothing is evaluated, read, recorded or
     * dispatched.
     *
     * @return \SineMacula\Laravel\Authorization\Evaluation\Explanation
     */
    public function explain(): Explanation
    {
        return Explanation::of($this);
    }
}
