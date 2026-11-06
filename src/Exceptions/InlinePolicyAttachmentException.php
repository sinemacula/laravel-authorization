<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Thrown when an inline policy would be attached to a grantee other than the
 * one it belongs to.
 *
 * An inline policy belongs to one grantee, named by its `owner_type` and
 * `owner_id` columns, and is attached to that grantee alone. Every write path
 * refuses another grantee: the identity traits, the grant service, and a write
 * through the `policies()` relation. To give another grantee the same
 * statements, create a managed policy, or an inline policy of its own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class InlinePolicyAttachmentException extends \LogicException
{
    /**
     * Create a new exception instance.
     *
     * @param  string  $policyName
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $owner
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     */
    public function __construct(

        /** The name of the inline policy. */
        private readonly string $policyName,

        /** The grantee the policy belongs to. */
        private readonly Reference $owner,

        /** The grantee the policy was to be attached to. */
        private readonly Reference $grantee,
    ) {
        parent::__construct(
            "Inline policy '{$policyName}' belongs to {$owner->type}:{$owner->id} and is attached to it alone, not to {$grantee->type}:{$grantee->id}.",
        );
    }

    /**
     * Return the name of the inline policy.
     *
     * @return string
     */
    public function getPolicyName(): string
    {
        return $this->policyName;
    }

    /**
     * Return the grantee the policy belongs to.
     *
     * @return \SineMacula\Laravel\Authorization\Support\Reference
     */
    public function getOwner(): Reference
    {
        return $this->owner;
    }

    /**
     * Return the grantee the policy was to be attached to.
     *
     * @return \SineMacula\Laravel\Authorization\Support\Reference
     */
    public function getGrantee(): Reference
    {
        return $this->grantee;
    }
}
