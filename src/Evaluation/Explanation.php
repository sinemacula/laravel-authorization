<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

use SineMacula\Laravel\Authorization\Evaluation\Enums\ConditionOutcome;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionEffect;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\Enums\TraceOutcome;

/**
 * Why a decision was made (AUTHZ-11.5, N88): the verdict, its reason and the
 * stage that decided it; the statements that decided it, every one when several
 * did, or the cause that is no statement (a cap that refused, the permission
 * held, the reason of an early refusal); the evidence of each stage the
 * decision reached, in order; the stages it never reached, marked as not
 * evaluated rather than guessed at; where each grant that allowed it came from;
 * each authentication requirement that alone kept an allow from applying, by
 * its part names and unmet parts; and what the check asked.
 *
 * It is a projection of the decision alone: nothing is evaluated, read,
 * recorded or dispatched to make or render it. A decision made in explain mode
 * carries every condition test with its outcome, the references that could not
 * be resolved, the grants' provenance and the request (see `DecisionEvidence`);
 * one made without it, the last decision of an everyday check say, explains
 * with what it has, and marks the rest `not recorded (explain mode off)`.
 *
 * It never holds a value: no context or attribute value, operand, interpolated
 * string, model, raw context, session or fingerprint (AUTHZ-8.8), only names,
 * references and outcomes, which still disclose how the policies are built, so
 * it is for those allowed to see them. `toText()` renders it for reading, every
 * name escaped so none can inject markup or control characters, and
 * `toArray()`, which `jsonSerialize()` returns, renders it in a stable schema
 * carrying its `version`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Explanation implements \JsonSerializable
{
    /** @var int The version of the schema `toArray()` renders. */
    public const int VERSION = 1;

    /** @var string What the explanation says of the evidence a decision made without explain mode did not record. */
    public const string NOT_RECORDED = 'not recorded (explain mode off)';

    /**
     * Create a new explanation.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionEffect  $effect
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null  $reason
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage  $stage
     * @param  list<\SineMacula\Laravel\Authorization\Evaluation\StatementReference>  $statements
     * @param  array{kind: string, names: list<string>}|null  $cause
     * @param  list<\SineMacula\Laravel\Authorization\Evaluation\TraceEntry>  $steps
     * @param  list<\SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage>  $notEvaluated
     * @param  list<\SineMacula\Laravel\Authorization\Evaluation\UnmetRequirement>  $requirements
     * @param  list<string>  $keys
     * @param  \SineMacula\Laravel\Authorization\Evaluation\DecisionEvidence|null  $evidence
     */
    private function __construct(

        /** Whether the check was allowed or denied. */
        public DecisionEffect $effect,

        /** Why it was denied; null when it was allowed. */
        public ?DecisionReason $reason,

        /** The stage that decided it. */
        public DecisionStage $stage,

        /** The statements that decided it, every one when several did. */
        public array $statements,

        /** What decided it when no statement did: its kind (`guardrail`, `boundary`, `session`, `administration`, `permission` or `reason`) and the names of the caps or permission; null when statements did. */
        public ?array $cause,

        /** The evidence of every stage the decision reached, in order. */
        public array $steps,

        /** The stages the decision never reached, in order. */
        public array $notEvaluated,

        /** Each authentication requirement that alone kept an allow from applying. */
        public array $requirements,

        /** Each context key the decision depended on. */
        public array $keys,

        /** The evidence of an explained check; null for a decision made without explain mode. */
        public ?DecisionEvidence $evidence,
    ) {}

    /**
     * Return the explanation of the decision, from what it carries alone.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Decision  $decision
     * @return self
     */
    public static function of(Decision $decision): self
    {
        return new self(
            $decision->effect,
            $decision->reason,
            $decision->stage,
            $decision->statements,
            self::causeOf($decision),
            $decision->trace,
            self::notEvaluatedBy($decision),
            $decision->requirements,
            $decision->keys(),
            $decision->evidence,
        );
    }

    /**
     * Determine whether the check was allowed.
     *
     * @return bool
     */
    public function isAllowed(): bool
    {
        return $this->effect === DecisionEffect::ALLOW;
    }

    /**
     * Determine whether the explanation carries the evidence of an explained
     * check, rather than only what an everyday decision records.
     *
     * @return bool
     */
    public function isDetailed(): bool
    {
        return $this->evidence !== null;
    }

    /**
     * Return the key of every context key a test found missing and could not be
     * decided without, and of every `${…}` reference that could not be
     * resolved, each once, in the order met; empty for a decision made without
     * explain mode, which records neither.
     *
     * @return list<string>
     */
    public function missingKeys(): array
    {
        $keys = [];

        foreach ($this->steps as $step) {
            $keys = [...$keys, ...$step->unresolved];

            foreach ($step->tests ?? [] as $test) {
                $keys = [...$keys, ...($test->outcome === ConditionOutcome::MISSING ? [$test->key] : []), ...$test->unresolved];
            }
        }

        return \array_values(\array_unique($keys));
    }

    /**
     * Return the explanation as text, for reading, every name escaped (see
     * `ExplanationText`).
     *
     * @return string
     */
    public function toText(): string
    {
        return ExplanationText::render($this);
    }

    /**
     * Return the explanation in its stable schema, version 1: what was decided
     * and by what, the evidence of each stage reached, grouped by stage, the
     * stages not evaluated, the grants' provenance, the requirements, the keys
     * depended on and missing, and the request, the evidence a decision made
     * without explain mode did not record given as `not recorded (explain mode
     * off)`.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        $isDetailed = $this->isDetailed();
        $request    = $this->evidence?->request;

        return [
            'version'       => self::VERSION,
            'effect'        => $this->effect->value,
            'reason'        => $this->reason?->value,
            'stage'         => $this->stage->value,
            'decided_by'    => ['statements' => \array_map(self::statementArray(...), $this->statements), 'cause' => $this->cause],
            'stages'        => $this->stagesArray($isDetailed),
            'not_evaluated' => \array_map(static fn (DecisionStage $stage): string => $stage->value, $this->notEvaluated),
            'grants'        => $isDetailed ? \array_map(static fn (GrantProvenance $grant): array => $grant->toArray(), $this->evidence->grants ?? []) : self::NOT_RECORDED,
            'requirements'  => \array_map(static fn (UnmetRequirement $unmet): array => ['names' => $unmet->requirement->names(), 'unmet' => $unmet->unmet], $this->requirements),
            'keys'          => $this->keys,
            'missing_keys'  => $isDetailed ? $this->missingKeys() : self::NOT_RECORDED,
            'request'       => $request?->toArray() ?? self::NOT_RECORDED,
            'evidence'      => $isDetailed ? 'recorded' : self::NOT_RECORDED,
        ];
    }

    /**
     * Return the explanation as `toArray()` renders it, for `json_encode()`.
     *
     * @return array<string, mixed>
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }

    /**
     * Return the statement reference in the schema: its policy, stored key,
     * position, sid and the resource its policy is attached to.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\StatementReference|null  $reference
     * @return array{policy: string, policy_id: string|null, index: int, sid: string|null, resource: string|null}|null
     */
    public static function statementArray(?StatementReference $reference): ?array
    {
        if ($reference === null) {
            return null;
        }

        return ['policy' => $reference->policy, 'policy_id' => $reference->policyId, 'index' => $reference->index, 'sid' => $reference->sid, 'resource' => $reference->resource];
    }

    /**
     * Return the steps grouped by the stage each belongs to, the stages in the
     * order first reached.
     *
     * @param  bool  $isDetailed
     * @return list<array{stage: string, steps: list<array<string, mixed>>}>
     */
    private function stagesArray(bool $isDetailed): array
    {
        $stages = [];

        foreach ($this->steps as $step) {
            $stages[$step->stage->value][] = self::stepArray($step, $isDetailed);
        }

        return \array_map(static fn (string $stage, array $steps): array => ['stage' => $stage, 'steps' => $steps], \array_keys($stages), \array_values($stages));
    }

    /**
     * Return one step in the schema: what it found, what it is about, the
     * condition keys it tested with whether each held, the references its
     * statement names, and, for a statement's step, each test with what it
     * found and the references that could not be resolved, or `not recorded`
     * for a decision made without explain mode.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\TraceEntry  $step
     * @param  bool  $isDetailed
     * @return array<string, mixed>
     */
    private static function stepArray(TraceEntry $step, bool $isDetailed): array
    {
        $conditions = \array_map(
            static fn (string $key, bool $holds): array => ['key' => $key, 'held' => $holds],
            \array_map(\strval(...), \array_keys($step->conditions)),
            \array_values($step->conditions),
        );
        $tests    = $step->tests                    === null ? [] : \array_map(static fn (ConditionResult $test): array => $test->toArray(), $step->tests);
        $recorded = $isDetailed || $step->statement === null || !self::isAssessed($step->outcome);

        return [
            'outcome'      => $step->outcome->value,
            'statement'    => self::statementArray($step->statement),
            'cap'          => $step->cap,
            'permission'   => $step->permission,
            'conditions'   => $conditions,
            'dependencies' => $step->dependencies,
            'tests'        => $recorded ? $tests : self::NOT_RECORDED,
            'unresolved'   => $recorded ? $step->unresolved : self::NOT_RECORDED,
        ];
    }

    /**
     * Determine whether a step with the outcome assessed its statement's
     * conditions, so an explained check records its tests.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\TraceOutcome  $outcome
     * @return bool
     */
    private static function isAssessed(TraceOutcome $outcome): bool
    {
        return \in_array($outcome, [TraceOutcome::MATCHED, TraceOutcome::CONDITION_FAILED, TraceOutcome::UNDECIDABLE, TraceOutcome::INVALID], true);
    }

    /**
     * Return what decided the decision when no statement did: the caps that
     * refused it at a cap or administration stage, the permission held that
     * allowed it, or else its reason alone; null when statements decided it.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Decision  $decision
     * @return array{kind: string, names: list<string>}|null
     */
    private static function causeOf(Decision $decision): ?array
    {
        if ($decision->statements !== []) {
            return null;
        }

        $isCap = \in_array($decision->stage, [DecisionStage::GUARDRAIL, DecisionStage::BOUNDARY, DecisionStage::SESSION, DecisionStage::ADMINISTRATION], true);
        $names = [];

        foreach ($decision->trace as $step) {
            $names = [...$names, ...self::causeNamed($step, $isCap ? $decision->stage : null)];
        }

        $kind = match (true) {
            $isCap        => $decision->stage->value,
            $names !== [] => 'permission',
            default       => 'reason',
        };

        return ['kind' => $kind, 'names' => $names];
    }

    /**
     * Return the name the step gives the cause: at the cap stage that decided,
     * the cap it names as refusing; when no cap decided, the permission it
     * names as held; otherwise none.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\TraceEntry  $step
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage|null  $capStage
     * @return list<string>
     */
    private static function causeNamed(TraceEntry $step, ?DecisionStage $capStage): array
    {
        if ($capStage === null) {
            return $step->outcome === TraceOutcome::HELD && $step->permission !== null ? [$step->permission] : [];
        }

        return $step->stage === $capStage && $step->outcome === TraceOutcome::REFUSED && $step->cap !== null ? [$step->cap] : [];
    }

    /**
     * Return the stages the decision never reached: none for an allow, which
     * every stage that could refuse it let through, and, for a denial, every
     * stage after the one that decided it that its trace does not reach.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Decision  $decision
     * @return list<\SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage>
     */
    private static function notEvaluatedBy(Decision $decision): array
    {
        if ($decision->isAllowed()) {
            return [];
        }

        $reached = \array_map(static fn (TraceEntry $step): DecisionStage => $step->stage, $decision->trace);
        $stages  = DecisionStage::cases();
        $after   = \array_slice($stages, (int) \array_search($decision->stage, $stages, true) + 1);

        return \array_values(\array_filter($after, static fn (DecisionStage $stage): bool => !\in_array($stage, $reached, true)));
    }
}
