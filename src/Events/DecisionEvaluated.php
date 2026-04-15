<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events;

use SineMacula\Laravel\Authorization\Evaluation\EvaluationResult;

/**
 * Dispatched every time the authorization manager completes an
 * evaluation.
 *
 * Carries the principal, action, resource, context, and the full
 * {@see EvaluationResult} — including the reproducible trace — so
 * audit listeners can persist the decision verbatim.
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
        public ?object $principal,
        public string $action,
        public ?string $resource,
        public array $context,
        public EvaluationResult $result,
    ) {}
}
