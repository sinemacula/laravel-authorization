<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

/**
 * Thrown when an inline policy would be saved as a system policy.
 *
 * An inline policy belongs to one grantee and is deleted with it, while a
 * system policy refuses to be deleted, so the two cannot meet: a system inline
 * policy would outlive its grantee and stop `authorization:prune` from deleting
 * it. The policy observer's `saving` hook raises this exception before the row
 * reaches the database, on create and on update alike. A platform-shipped
 * policy is a managed one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class SystemInlinePolicyException extends \LogicException
{
    /**
     * Create a new exception instance naming the policy.
     *
     * @param  string  $policyName
     */
    public function __construct(

        /** The name of the policy refused. */
        private readonly string $policyName,
    ) {
        parent::__construct(
            "Cannot save inline policy '{$policyName}' as a system policy: "
            . 'an inline policy is deleted with its grantee, so only a managed policy can be a system one.',
        );
    }

    /**
     * Return the name of the policy refused.
     *
     * @return string
     */
    public function getPolicyName(): string
    {
        return $this->policyName;
    }
}
