<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Permissions\Exceptions;

use SineMacula\Laravel\Iam\Permissions\Evaluation\EvaluationResult;

/**
 * Authorization exception.
 *
 * Thrown when a principal is not authorized to perform the
 * requested action. Carries the evaluation result for inspection
 * by exception handlers.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
class AuthorizationException extends \RuntimeException
{
    /**
     * Create a new authorization exception instance.
     *
     * @param  string  $action
     * @param  string|null  $resource
     * @param  \SineMacula\Laravel\Iam\Permissions\Evaluation\EvaluationResult|null  $result
     */
    public function __construct(
        public readonly string $action,
        public readonly ?string $resource = null,
        public readonly ?EvaluationResult $result = null,
    ) {
        $message = $resource !== null
            ? "Unauthorized action '{$action}' on resource '{$resource}'"
            : "Unauthorized action '{$action}'";

        parent::__construct($message, 403);
    }
}
