<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events;

use SineMacula\Laravel\Authorization\Evaluation\EvaluationResult;

/**
 * Dispatched every time the authorization manager completes an evaluation —
 * `can()`, `authorize()`, `evaluate()`, every path.
 *
 * Carries the principal, action, resource, context, and the full evaluation
 * result — including the reproducible trace — so audit listeners can persist
 * the decision verbatim. Listeners that want a denial-only view filter on
 * `$event->result->allowed === false`; the separate `AuthorizationFailed` event
 * covers the narrower hard-denial signal that fires only when `authorize()` is
 * about to throw.
 *
 * Part of the SemVer-stable event API; breaking changes require a major version
 * bump.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class DecisionEvaluated
{
    /**
     * Create a new event instance.
     *
     * @param  object|null  $principal
     * @param  string  $action
     * @param  string|null  $resource
     * @param  array<string, mixed>  $context
     * @param  \SineMacula\Laravel\Authorization\Evaluation\EvaluationResult  $result
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

        /** Final evaluation result, including the reproducible trace. */
        public EvaluationResult $result,

    ) {}
}
