<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events;

use SineMacula\Laravel\Authorization\Evaluation\EvaluationResult;

/**
 * Dispatched immediately before an authorization exception is thrown
 * from the manager's `authorize()` entry point.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class AuthorizationFailed
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

        /** Acting principal at the time of evaluation, or null when anonymous. */
        public ?object $principal,

        /** Action string that was checked. */
        public string $action,

        /** Resource identifier the action targets, or null for resource-less checks. */
        public ?string $resource,

        /** Evaluation context passed through to policy statements. */
        public array $context,

        /** Final evaluation result, including the reproducible statement trace. */
        public EvaluationResult $result,

    ) {}
}
