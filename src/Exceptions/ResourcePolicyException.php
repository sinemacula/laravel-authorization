<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

/**
 * Thrown when a policy would be attached, or rewritten, against the rule for
 * the `principals` of its statements (AUTHZ-7.3).
 *
 * A policy attached to a resource or a resource type is a managed policy whose
 * every allow statement names its principals, the subjects it applies to; its
 * denies take none and apply to everyone. A policy attached to a grantee or a
 * role names no principals. Attaching an inline policy to a resource, a policy
 * with an allow that names no principals to a resource, or a policy naming
 * principals to a grantee or a role, is refused, and so is rewriting an
 * attached policy so that it breaks the rule for where it is attached.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class ResourcePolicyException extends \LogicException
{
    /**
     * Create a new exception instance.
     *
     * @param  string  $message
     * @param  string  $policyName
     * @param  list<int>  $statements
     */
    private function __construct(

        // What the refusal says, handed to the parent exception.
        string $message,

        /** The name of the policy refused. */
        private readonly string $policyName,

        /** The positions of the statements that break the rule, from zero. */
        private readonly array $statements = [],
    ) {
        parent::__construct($message);
    }

    /**
     * Return the refusal of an inline policy attached to a resource.
     *
     * @param  string  $policyName
     * @return self
     */
    public static function inline(string $policyName): self
    {
        return new self("Inline policy '{$policyName}' belongs to one grantee and cannot be attached to a resource; attach a managed policy.", $policyName);
    }

    /**
     * Return the refusal of a policy, attached to a resource, whose allow
     * statements at the positions name no principals.
     *
     * @param  string  $policyName
     * @param  list<int>  $statements
     * @return self
     */
    public static function principalsRequired(string $policyName, array $statements): self
    {
        return new self(
            "Policy '{$policyName}' is attached to a resource, so every allow statement names its principals; " . self::positions($statements) . ' name none.',
            $policyName,
            $statements,
        );
    }

    /**
     * Return the refusal of a policy, attached to a grantee or a role, whose
     * statements at the positions name principals.
     *
     * @param  string  $policyName
     * @param  list<int>  $statements
     * @return self
     */
    public static function principalsRefused(string $policyName, array $statements): self
    {
        return new self(
            "Policy '{$policyName}' is attached to a grantee or a role, so no statement names principals, which only a resource policy's allows do; "
                . self::positions($statements) . ' name some.',
            $policyName,
            $statements,
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

    /**
     * Return the positions of the statements that break the rule, from zero;
     * none for an inline policy.
     *
     * @return list<int>
     */
    public function getStatements(): array
    {
        return $this->statements;
    }

    /**
     * Describe the statements at the positions for the message.
     *
     * @param  list<int>  $statements
     * @return string
     */
    private static function positions(array $statements): string
    {
        return 'statement ' . \implode(', ', \array_map(static fn (int $index): string => "#{$index}", $statements));
    }
}
