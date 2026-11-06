<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Exceptions;

use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Thrown when a guardrail would be changed, or the policy one is edited or
 * deleted, against the rules guardrails keep (AUTHZ-7.6), naming the reason.
 *
 * - `not_permitted`: the actor may not change the guardrails of the scope. It
 *   must hold `authorization:guardrails:manage` effectively, through a grant
 *   whose reach covers the scope from above it: for a tenant, a grant held at
 *   an ancestor of the tenant that reaches below it, or platform-wide, never
 *   one held within the tenant itself; for the platform, a platform-wide grant.
 * - `inline`: an inline policy belongs to one grantee and is deleted with it,
 *   so it is never a guardrail.
 * - `in_use`: the policy is a guardrail, so it is neither edited nor deleted,
 *   which would change or lift the cap without the guardrail service, until
 *   each guardrail it is has been removed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class GuardrailException extends \LogicException
{
    /** @var string The actor may not change the guardrails of the scope. */
    public const string NOT_PERMITTED = 'not_permitted';

    /** @var string An inline policy cannot be a guardrail. */
    public const string INLINE = 'inline';

    /** @var string The policy is a guardrail, so it cannot be edited or deleted. */
    public const string IN_USE = 'in_use';

    /**
     * Create a new exception instance.
     *
     * @param  string  $message
     * @param  string  $reason
     * @param  string|null  $policyName
     * @param  list<\SineMacula\Laravel\Authorization\Support\Reference|null>  $tenants
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     */
    private function __construct(

        // What the refusal says, handed to the parent exception.
        string $message,

        /** Why the change was refused, one of the class's reason constants. */
        private readonly string $reason,

        /** The name of the policy refused; null when no one policy is. */
        private readonly ?string $policyName = null,

        /** The scopes the refusal is about, each a tenant, or null for the platform. */
        private readonly array $tenants = [],

        /** The actor refused; null when the refusal is about no actor. */
        private readonly ?Reference $actor = null,
    ) {
        parent::__construct($message);
    }

    /**
     * Return the refusal of an actor that may not change the guardrails of the
     * tenant, or of the platform when the tenant is null.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $actor
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @return self
     */
    public static function notPermitted(Reference $actor, ?Reference $tenant): self
    {
        $permission = PackagePermissions::GUARDRAILS_MANAGE;
        $scope      = $tenant === null ? 'the platform' : "tenant '{$tenant->type}:{$tenant->id}'";
        $grant      = $tenant === null
            ? 'a platform-wide grant'
            : 'a grant held at an ancestor of the tenant that reaches it, or a platform-wide one, never one held within the tenant';

        return new self(
            "'{$actor->type}:{$actor->id}' may not change the guardrails of {$scope}: it must hold '{$permission}' through {$grant}.",
            self::NOT_PERMITTED,
            null,
            [$tenant],
            $actor,
        );
    }

    /**
     * Return the refusal of an inline policy set as a guardrail.
     *
     * @param  string  $policyName
     * @return self
     */
    public static function inline(string $policyName): self
    {
        return new self("Inline policy '{$policyName}' belongs to one grantee and cannot be set as a guardrail; set a managed policy.", self::INLINE, $policyName);
    }

    /**
     * Return the refusal of an edit or a deletion of a policy in use as a
     * guardrail on the tenants, null for the platform.
     *
     * @param  string  $policyName
     * @param  list<\SineMacula\Laravel\Authorization\Support\Reference|null>  $tenants
     * @param  string  $change
     * @return self
     */
    public static function inUse(string $policyName, array $tenants, string $change): self
    {
        $named = \implode(', ', \array_map(static fn (?Reference $tenant): string => $tenant === null ? 'the platform' : "{$tenant->type}:{$tenant->id}", $tenants));

        $message = "Policy '{$policyName}' is a guardrail on {$named}; remove each guardrail through the guardrail service before {$change} the policy.";

        return new self($message, self::IN_USE, $policyName, $tenants);
    }

    /**
     * Return why the change was refused, one of the class's reason constants.
     *
     * @return string
     */
    public function getReason(): string
    {
        return $this->reason;
    }

    /**
     * Return the name of the policy refused, or null when no one policy is.
     *
     * @return string|null
     */
    public function getPolicyName(): ?string
    {
        return $this->policyName;
    }

    /**
     * Return the scopes the refusal is about, each a tenant, or null for the
     * platform: the scope the actor may not change, or every scope the policy
     * is a guardrail on.
     *
     * @return list<\SineMacula\Laravel\Authorization\Support\Reference|null>
     */
    public function getTenants(): array
    {
        return $this->tenants;
    }

    /**
     * Return the actor refused, or null when the refusal is about no actor.
     *
     * @return \SineMacula\Laravel\Authorization\Support\Reference|null
     */
    public function getActor(): ?Reference
    {
        return $this->actor;
    }
}
