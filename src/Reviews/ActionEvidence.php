<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Reviews;

use SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect;
use SineMacula\Laravel\Authorization\Reviews\Enums\EvidenceKind;

/**
 * What gives the action a review of holdings filtered by one asks about (see
 * `ReviewQuery::forAction()`), on each of its rows, and where the route giving
 * it reaches.
 *
 * It is evidence of a stored grant route, never a decision (D22): a permission
 * or an allow statement may still be defeated by a deny, a boundary, a
 * guardrail, a resource restriction or a session cap, and conditions, resource
 * patterns and requirements are reported as present but never evaluated; only
 * `check()` says whether an operation is allowed. Its shape, under the row's
 * `action_evidence` key:
 *
 * - `action`: the action asked about, literal;
 * - `evidence`: `permission` or `policy_statement` (see `Enums\EvidenceKind`);
 * - `effect`: `allow` for a permission, or a policy with an allow statement
 *   naming the action; `deny` for a policy whose statements naming it only
 *   deny, which is never positive authority; null for a policy whose document
 *   could not be read;
 * - `guard`: the guard a permission is scoped to, null for every guard and for
 *   a policy;
 * - `complete`: false only for a policy whose stored document is invalid, so
 *   whether it names the action is unknown; the route is kept, never dropped;
 * - `has_deny`, `has_conditions`, `has_resource_patterns`, `has_requirements`:
 *   whether any statement naming the action denies, carries conditions, names
 *   resources, or states an authentication requirement; false for a permission;
 * - `reach`: where the route reaches, compactly (see `Enums\ReachKind`): its
 *   `kind`, `node`, `subtree` or `platform`, then the tenant, application and
 *   reach below as an origin scope holds them. For a policy through a role it
 *   is where the role's grant and the attachment hold together, never the wider
 *   of the two.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ActionEvidence
{
    /**
     * Create new action evidence.
     *
     * @param  string  $action
     * @param  \SineMacula\Laravel\Authorization\Reviews\Enums\EvidenceKind  $evidence
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect|null  $effect
     * @param  \SineMacula\Laravel\Authorization\Reviews\OriginScope  $reach
     * @param  string|null  $guard
     * @param  bool  $isComplete
     * @param  bool  $hasDeny
     * @param  bool  $hasConditions
     * @param  bool  $hasResourcePatterns
     * @param  bool  $hasRequirements
     */
    public function __construct(

        /** The action asked about. */
        public string $action,

        /** What gives the action: a permission or a policy statement. */
        public EvidenceKind $evidence,

        /** Allow, or deny for a policy that only denies the action; null when its document could not be read. */
        public ?PolicyEffect $effect,

        /** Where the route reaches, compactly. */
        public OriginScope $reach,

        /** The guard a permission is scoped to; null for every guard and for a policy. */
        public ?string $guard = null,

        /** Whether the evidence could be read whole; false for a policy whose stored document is invalid. */
        public bool $isComplete = true,

        /** Whether a statement naming the action denies it. */
        public bool $hasDeny = false,

        /** Whether a statement naming the action carries conditions, never evaluated here. */
        public bool $hasConditions = false,

        /** Whether a statement naming the action names resources, never matched here. */
        public bool $hasResourcePatterns = false,

        /** Whether a statement naming the action states an authentication requirement, never judged here. */
        public bool $hasRequirements = false,
    ) {}

    /**
     * Return the evidence of a policy whose stored document could not be read,
     * so whether it names the action is unknown.
     *
     * @param  string  $action
     * @param  \SineMacula\Laravel\Authorization\Reviews\OriginScope  $reach
     * @return self
     */
    public static function unreadable(string $action, OriginScope $reach): self
    {
        return new self($action, EvidenceKind::POLICY_STATEMENT, null, $reach, isComplete: false);
    }

    /**
     * Return the evidence as plain values, in its versioned shape.
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @formatter:off
     *
     * @return array{action: string, evidence: string, effect: string|null, guard: string|null, complete: bool, has_deny: bool, has_conditions: bool, has_resource_patterns: bool, has_requirements: bool, reach: array<string, mixed>}
     *
     * @formatter:on
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     */
    public function toArray(): array
    {
        return [
            'action'                => $this->action,
            'evidence'              => $this->evidence->value,
            'effect'                => $this->effect?->value,
            'guard'                 => $this->guard,
            'complete'              => $this->isComplete,
            'has_deny'              => $this->hasDeny,
            'has_conditions'        => $this->hasConditions,
            'has_resource_patterns' => $this->hasResourcePatterns,
            'has_requirements'      => $this->hasRequirements,
            'reach'                 => ['kind' => $this->reach->reach()->value, ...$this->reach->toArray()],
        ];
    }
}
