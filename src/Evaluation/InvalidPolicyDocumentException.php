<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

/**
 * Thrown when a persisted policy document cannot be parsed into a
 * valid policy value object.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
class InvalidPolicyDocumentException extends \RuntimeException
{
    /**
     * Create a new exception instance.
     *
     * @param  string  $policyName
     * @param  string  $reason
     * @param  \Throwable|null  $previous
     */
    public function __construct(

        /** Name of the policy whose document failed to parse. */
        private readonly string $policyName,

        string $reason,
        ?\Throwable $previous = null,

    ) {
        parent::__construct(
            "Invalid policy document '{$policyName}': {$reason}",
            400,
            $previous,
        );
    }

    /**
     * Return the name of the policy whose document failed to parse.
     *
     * @return string
     */
    public function getPolicyName(): string
    {
        return $this->policyName;
    }
}
