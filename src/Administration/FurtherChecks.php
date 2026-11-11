<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Administration;

use SineMacula\Laravel\Authorization\Evaluation\CheckSources;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\DecisionMemory;
use SineMacula\Laravel\Authorization\Evaluation\RequirementFreshness;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceReference;

/**
 * What the administration stage of one decision may ask of the decision
 * pipeline (see `OperationConstraints`): the acting subject, the tenant the
 * check is made from, before the operation's own tenant is put in place (see
 * `ResourceScope`), so the owner rule can compare it, and further checks of the
 * same subject, each decided as the pipeline decides any check, through every
 * stage up to the allow, in the scope in place when it is asked, but never
 * through the administration stage itself, so a constraint that decides the
 * operation's own action again in another scope cannot recurse.
 *
 * What could limit a right across a reach is read once per decision for each
 * right, reach and scope in place (see `limited()`), so a change that weighs
 * the same right for every role, permission or policy it hands out reads its
 * limits once, until the decisions are forgotten (see `DecisionMemory`).
 *
 * Every authentication requirement a further check reads is part of the
 * decision it is made for: the checks keep the requirements each further
 * decision read, and carry them into the decision that leaves the stage,
 * allowed or refused (see `carriedInto()`), so that decision names every
 * requirement read for it and is reused no longer than any of them stays met.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class FurtherChecks
{
    /** @var array<string, bool> Whether each right was found limited, keyed by the right, the reach and the scope in place. */
    private array $limits = [];

    /** @var int|null The generation of the decisions the limits were found in (see `DecisionMemory`), or null before any is. */
    private ?int $generation = null;

    /** @var \SineMacula\Laravel\Authorization\Evaluation\RequirementFreshness|null How long the further checks decided so far may be reused; null while none read a requirement. */
    private ?RequirementFreshness $freshness = null;

    /** @var list<string> The name of each part of every requirement the further checks decided so far read, any of them repeated. */
    private array $requirementsRead = [];

    /**
     * Create the further checks of one decision.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  \Closure(string, \SineMacula\Laravel\Authorization\Support\ResourceReference|null): \SineMacula\Laravel\Authorization\Evaluation\Decision  $decide
     * @param  \Closure(string): (\SineMacula\Laravel\Authorization\Evaluation\CheckSources|null)  $sources
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $from
     */
    public function __construct(

        /** The acting subject the decision is about. */
        public readonly Subject $subject,

        /** Decides a further check of the subject in the scope in place. */
        private readonly \Closure $decide,

        /** Gathers the sources of a further check of the subject, on no resource, in the scope in place, or null when a document cannot be read. */
        private readonly \Closure $sources,

        /** The tenant the check is made from; null for the platform. */
        public readonly ?Reference $from = null,
    ) {}

    /**
     * Decide the action for the subject on the resource, or on none, in the
     * scope in place, through every stage up to the allow, keeping the
     * authentication requirements the decision read (see `carriedInto()`).
     *
     * @param  string  $action
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference|null  $resource
     * @return \SineMacula\Laravel\Authorization\Evaluation\Decision
     */
    public function decide(string $action, ?ResourceReference $resource = null): Decision
    {
        $decision = ($this->decide)($action, $resource);

        $this->freshness        = RequirementFreshness::stricterOf($this->freshness, $decision->freshness);
        $this->requirementsRead = [...$this->requirementsRead, ...$decision->requirementsRead];

        return $decision;
    }

    /**
     * Return the decision with every authentication requirement the further
     * checks decided so far read added to its own, and reusable no longer than
     * any of them stays met, or the decision itself when neither read one.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Decision  $decision
     * @return \SineMacula\Laravel\Authorization\Evaluation\Decision
     */
    public function carriedInto(Decision $decision): Decision
    {
        return $decision->withFreshness($this->freshness, $this->requirementsRead);
    }

    /**
     * Gather the sources a check of the action for the subject, on no resource,
     * is decided from, in the scope in place, or null when a policy, boundary
     * or guardrail document among them cannot be read.
     *
     * @param  string  $action
     * @return \SineMacula\Laravel\Authorization\Evaluation\CheckSources|null
     */
    public function sources(string $action): ?CheckSources
    {
        return ($this->sources)($action);
    }

    /**
     * Return whether the right named by the key is limited across its reach,
     * working it out through the callback the first time the key is asked and
     * remembering it for the rest of this decision, or until the decisions are
     * forgotten (see `DecisionMemory`), when it is worked out again.
     *
     * @param  string  $key
     * @param  \Closure(): bool  $limit
     * @return bool
     */
    public function limited(string $key, \Closure $limit): bool
    {
        $generation = DecisionMemory::current()->generation();

        // Found before the decisions were forgotten, worked out again.
        if ($generation !== $this->generation) {
            $this->limits     = [];
            $this->generation = $generation;
        }

        $known = $this->limits[$key] ?? null;

        if ($known !== null) {
            return $known;
        }

        $isLimited = $limit();

        $this->limits[$key] = $isLimited;

        return $isLimited;
    }
}
