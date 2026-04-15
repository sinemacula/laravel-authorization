<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events;

use SineMacula\Laravel\Authorization\Evaluation\EvaluationResult;

/**
 * Dispatched immediately before an {@see \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException}
 * is thrown from the manager's `authorize()` entry point.
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
        public ?object $principal,
        public string $action,
        public ?string $resource,
        public array $context,
        public EvaluationResult $result,
    ) {}
}
