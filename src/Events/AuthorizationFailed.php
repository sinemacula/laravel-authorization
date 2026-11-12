<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events;

/**
 * Dispatched immediately before an authorization exception is thrown from the
 * manager's `authorize()` entry point.
 *
 * This event is the hard-denial signal: it fires only when `authorize()` is
 * about to raise `AuthorizationException`. A `can()` call returning false is a
 * soft denial and does not fire this event — use `DecisionEvaluated` (which
 * reports every denial while `authorization.events.decisions.denials` is on)
 * and filter on `!$event->isAllowed()` when a full denial audit is required.
 * The split is intentional: hard-denial is rare and security-relevant;
 * soft-denial is routine and filterable.
 *
 * It implements `AuthorizationEvent`, as every event the package dispatches
 * does, and like `DecisionEvaluated` it is dispatched when the decision is
 * made, not after a commit, and carries what `DecisionEvent` carries:
 * references, names and ids, never the principal model, the caller's context or
 * a condition or attribute value (AUTHZ-15.4). The exception thrown carries the
 * full decision.
 *
 * Part of the SemVer-stable event API; breaking changes require a major version
 * bump.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class AuthorizationFailed extends DecisionEvent {}
