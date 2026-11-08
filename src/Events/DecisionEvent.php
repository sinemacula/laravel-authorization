<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events;

use SineMacula\Laravel\Authorization\Contracts\AuthorizationEvent;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\DecisionProvenance;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionEffect;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * What every decision event carries (AUTHZ-15.3, AUTHZ-15.4), as
 * `DecisionEvaluated` and `AuthorizationFailed` report it: the subject and its
 * identity, the previewer of a preview, the action, the resource, the tenant
 * and application the decision was made in, its effect and reason code, the
 * statements that decided it, whether it used a break-glass grant, and the
 * context keys it depended on.
 *
 * A snapshot of references, names and ids, never a model, the caller's context,
 * a session, or a condition or attribute value: the keys are names alone. The
 * subject and the identity are null when the decision had none, a guest's
 * included, and are never filled from the authenticated user. The tenant and
 * the application are the scope the decision was made in, never read from the
 * subject (see `DecisionProvenance`). The previewer is null for a decision that
 * is not a preview, and `usedBreakGlass` is false until break-glass grants
 * arrive. The decision itself, with its trace, is not carried: a listener that
 * needs it reads `Authorization::lastDecision()`.
 *
 * Decision events are dispatched when the decision is made, not after a commit,
 * since a denial is a fact even if the surrounding transaction rolls back.
 *
 * Part of the SemVer-stable event API; breaking changes require a major version
 * bump.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
abstract readonly class DecisionEvent implements AuthorizationEvent
{
    /**
     * Create a new event instance.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $subject
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $identity
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $previewer
     * @param  string  $action
     * @param  string|null  $resource
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  string|null  $application
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionEffect  $effect
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason|null  $reason
     * @param  list<\SineMacula\Laravel\Authorization\Evaluation\StatementReference>  $statements
     * @param  bool  $usedBreakGlass
     * @param  list<string>  $keys
     */
    final public function __construct(

        /** The principal the decision was about; null when it had none, or none that is a saved record. */
        public ?Reference $subject,

        /** The identity behind the principal; null when it had none, or none that is a saved record. */
        public ?Reference $identity,

        /** Whoever previewed the decision as the subject; null for a decision that is not a preview. */
        public ?Reference $previewer,

        /** The action checked. */
        public string $action,

        /** The resource the action targets, as `type:id`, `type:*` or the name given; null for none. */
        public ?string $resource,

        /** The tenant the decision was made in; null for none. */
        public ?Reference $tenant,

        /** The application the decision was made in; null for none. */
        public ?string $application,

        /** Whether the check was allowed or denied. */
        public DecisionEffect $effect,

        /** Why the check was denied; null when it was allowed. */
        public ?DecisionReason $reason,

        /** The statements that decided it, each by its policy's name, the stored policy's key, its index, its sid and, for a resource policy, the resource it is attached to, in the order assessed. */
        public array $statements,

        /** Whether a break-glass grant allowed the check; false until break-glass grants arrive. */
        public bool $usedBreakGlass,

        /** The name of each context key the decision depended on, never its value. */
        public array $keys,
    ) {}

    /**
     * Return the event reporting the decision on the action and the resource,
     * made with the provenance given.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\DecisionProvenance  $provenance
     * @param  string  $action
     * @param  string|null  $resource
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Decision  $decision
     * @return static
     */
    public static function of(DecisionProvenance $provenance, string $action, ?string $resource, Decision $decision): static
    {
        return new static(
            $provenance->subject,
            $provenance->identity,
            $provenance->previewer,
            $action,
            $resource,
            $provenance->tenant,
            $provenance->application,
            $decision->effect,
            $decision->reason,
            $decision->statements,
            false,
            $decision->keys(),
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
}
