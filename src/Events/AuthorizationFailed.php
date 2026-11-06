<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events;

use SineMacula\Laravel\Authorization\Contracts\AuthorizationEvent;
use SineMacula\Laravel\Authorization\Evaluation\Decision;

/**
 * Dispatched immediately before an authorization exception is thrown from the
 * manager's `authorize()` entry point.
 *
 * This event is the hard-denial signal: it fires only when `authorize()` is
 * about to raise `AuthorizationException`. A `can()` call returning false is a
 * soft denial and does not fire this event — use `DecisionEvaluated` (which
 * fires on every evaluation regardless of outcome) and filter on
 * `!$event->decision->isAllowed()` when a full denial audit is required. The
 * split is intentional: hard-denial is rare and security-relevant; soft-denial
 * is routine and filterable.
 *
 * It implements `AuthorizationEvent`, as every event the package dispatches
 * does, and like `DecisionEvaluated` it is dispatched when the decision is
 * made, not after a commit, and still carries the principal object, the context
 * and the decision as they were evaluated.
 *
 * Part of the SemVer-stable event API; breaking changes require a major version
 * bump.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class AuthorizationFailed implements AuthorizationEvent
{
    /**
     * Create a new event instance.
     *
     * @param  object|null  $principal
     * @param  string  $action
     * @param  string|null  $resource
     * @param  array<string, mixed>  $context
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Decision  $decision
     */
    public function __construct(

        /** Acting principal at evaluation time, or null when anonymous. */
        public ?object $principal,

        /** Action string that was checked. */
        public string $action,

        /** Resource identifier the action targets; null for resource-less. */
        public ?string $resource,

        /** Evaluation context passed through to policy statements. */
        public array $context,

        /** The decision, with its reason, deciding statements and trace. */
        public Decision $decision,
    ) {}
}
