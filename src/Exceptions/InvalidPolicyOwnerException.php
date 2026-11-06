<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

/**
 * Thrown when a policy is saved with only one of its owner columns set.
 *
 * Both-or-neither is the invariant, as it is for the tenant columns: a managed
 * policy has neither `owner_type` nor `owner_id`, an inline policy has both,
 * naming the grantee it belongs to. A half-set pair would belong to no grantee
 * yet refuse every attachment. The policy observer's `saving` hook raises this
 * exception before the row reaches the database.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class InvalidPolicyOwnerException extends \LogicException
{
    /** @var string The name of the policy refused. */
    private readonly string $policyName;

    /** @var string The owner column that is missing. */
    private readonly string $missingColumn;

    /**
     * Create a new exception instance naming the policy and the missing column.
     *
     * @param  string  $policyName
     * @param  string  $missingColumn
     */
    public function __construct(string $policyName, string $missingColumn)
    {
        $this->policyName    = $policyName;
        $this->missingColumn = $missingColumn;

        parent::__construct(\sprintf(
            'Cannot save policy \'%s\' with inconsistent owner columns: \'%s\' is required when the other owner column is set. '
            . 'Both columns must be null (a managed policy) or both must be set (an inline policy).',
            $policyName,
            $missingColumn,
        ));
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

    /**
     * Return the owner column that is missing.
     *
     * @return string
     */
    public function getMissingColumn(): string
    {
        return $this->missingColumn;
    }
}
