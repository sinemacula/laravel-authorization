<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events;

/**
 * Dispatched every time the authorization manager completes an evaluation —
 * `check()`, `can()`, `authorize()`, every path.
 *
 * Carries what `DecisionEvent` carries: references, names and ids, never the
 * principal model, the caller's context or a condition or attribute value
 * (AUTHZ-15.4). Listeners that want a denial-only view filter on
 * `!$event->isAllowed()`; the separate `AuthorizationFailed` event covers the
 * narrower hard-denial signal that fires only when `authorize()` is about to
 * throw. A listener that needs the full decision, with its trace, reads
 * `Authorization::lastDecision()`.
 *
 * It implements `AuthorizationEvent`, as every event the package dispatches
 * does. Unlike the change events, it is dispatched when the decision is made,
 * not after a commit, since a denial is a fact even if the surrounding
 * transaction rolls back.
 *
 * Part of the SemVer-stable event API; breaking changes require a major version
 * bump.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class DecisionEvaluated extends DecisionEvent {}
