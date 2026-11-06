<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Thrown when a permission boundary would be set, or its policy deleted,
 * against the rules boundaries keep (AUTHZ-7.4).
 *
 * A boundary is a managed policy set on a principal or an identity: an inline
 * policy, which belongs to one grantee and is deleted with it, is refused, and
 * so is a grantee that is never a subject's principal or identity, a role, a
 * permission or a policy, whose boundary no check would ever read. A policy in
 * use as a boundary is never deleted from under it, which would lift the cap
 * without a word: its deletion is refused, naming every grantee it bounds,
 * until each boundary is removed through the boundary service.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class BoundaryException extends \LogicException
{
    /**
     * Create a new exception instance.
     *
     * @param  string  $message
     * @param  string  $policyName
     * @param  list<\SineMacula\Laravel\Authorization\Support\Reference>  $grantees
     */
    private function __construct(

        // What the refusal says, handed to the parent exception.
        string $message,

        /** The name of the policy refused. */
        private readonly string $policyName,

        /** The grantees the policy bounds, for a refused deletion. */
        private readonly array $grantees = [],
    ) {
        parent::__construct($message);
    }

    /**
     * Return the refusal of an inline policy set as a boundary.
     *
     * @param  string  $policyName
     * @return self
     */
    public static function inline(string $policyName): self
    {
        return new self("Inline policy '{$policyName}' belongs to one grantee and cannot be set as a boundary; set a managed policy.", $policyName);
    }

    /**
     * Return the refusal of a boundary set on a grantee that is never a
     * subject's principal or identity: a role, a permission or a policy, the
     * kind named.
     *
     * @param  string  $policyName
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $grantee
     * @param  string  $kind
     * @return self
     */
    public static function notASubject(string $policyName, Reference $grantee, string $kind): self
    {
        return new self(
            "Policy '{$policyName}' cannot be set as the boundary of {$kind} '{$grantee->id}': a boundary caps a principal or an identity, never a {$kind}.",
            $policyName,
            [$grantee],
        );
    }

    /**
     * Return the refusal of the deletion of a policy in use as the boundary of
     * the grantees.
     *
     * @param  string  $policyName
     * @param  list<\SineMacula\Laravel\Authorization\Support\Reference>  $grantees
     * @return self
     */
    public static function inUse(string $policyName, array $grantees): self
    {
        $named = \implode(', ', \array_map(static fn (Reference $grantee): string => "{$grantee->type}:{$grantee->id}", $grantees));

        return new self("Policy '{$policyName}' is the boundary of {$named}; remove each boundary before deleting the policy.", $policyName, $grantees);
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
     * Return the grantees the refusal names: those the policy bounds for a
     * refused deletion, the role, permission or policy a boundary was refused
     * on, and none for an inline policy.
     *
     * @return list<\SineMacula\Laravel\Authorization\Support\Reference>
     */
    public function getGrantees(): array
    {
        return $this->grantees;
    }
}
