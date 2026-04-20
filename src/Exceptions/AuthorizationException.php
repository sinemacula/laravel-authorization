<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

use SineMacula\Laravel\Authorization\Evaluation\EvaluationResult;

/**
 * Thrown when the authorization manager's `authorize()` entry point denies a
 * request.
 *
 * Carries the full evaluation result, including the reproducible statement
 * trace, so consumers can persist the decision to an audit log without
 * re-running the check.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
class AuthorizationException extends \RuntimeException
{
    /**
     * Create a new authorization exception instance.
     *
     * @param  string  $action
     * @param  string|null  $resource
     * @param  \SineMacula\Laravel\Authorization\Evaluation\EvaluationResult  $result
     */
    public function __construct(

        /** Action string that triggered the denial. */
        private readonly string $action,

        /** Resource identifier the action targeted, or null when omitted. */
        private readonly ?string $resource,

        /** Full evaluation result captured at the moment of denial. */
        private readonly EvaluationResult $result,

    ) {
        $message = $resource !== null
            ? "Unauthorized action '{$action}' on resource '{$resource}'"
            : "Unauthorized action '{$action}'";

        parent::__construct($message, 403);
    }

    /**
     * Return the action that triggered the denial.
     *
     * @return string
     */
    public function getAction(): string
    {
        return $this->action;
    }

    /**
     * Return the resource (when supplied) that triggered the denial.
     *
     * @return string|null
     */
    public function getResource(): ?string
    {
        return $this->resource;
    }

    /**
     * Return the evaluation result, including the trace of every statement
     * considered during the check.
     *
     * @return \SineMacula\Laravel\Authorization\Evaluation\EvaluationResult
     */
    public function getResult(): EvaluationResult
    {
        return $this->result;
    }
}
