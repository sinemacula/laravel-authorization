<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Usage;

/**
 * Which of a subject's grants one tracked check weighed (N100), so only the
 * routes its decision rested on are noted, by the rules forward resolution
 * applied (see `DecisionRoutes`): the grantee whose permission matched the
 * action, the subject's own or, only when the subject's did not, its granting
 * identity's, and whether the subject's and its identity's attached policies
 * were read at all.
 *
 * One is made for each tracked check, and its permission is noted as the check
 * asks for it, so finding the routes reads nothing the check did not.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class WeighedGrants
{
    /** @var string|null The permission that matched the action, as it was granted; null until one does. */
    private ?string $permission = null;

    /** @var object|null The grantee whose permission matched the action; null until one does. */
    private ?object $grantee = null;

    /**
     * Create what a tracked check weighed.
     *
     * @param  bool  $areSubjectPoliciesWeighed
     * @param  bool  $areIdentityPoliciesWeighed
     */
    public function __construct(

        /** Whether the check read the policies attached to the subject itself, through the package's policy resolver. */
        public readonly bool $areSubjectPoliciesWeighed,

        /** Whether the check read the policies attached to the subject's identity. */
        public readonly bool $areIdentityPoliciesWeighed,
    ) {}

    /**
     * Note the permission that matched the action and the grantee holding it.
     *
     * @param  string  $permission
     * @param  object  $grantee
     * @return void
     */
    public function notePermission(string $permission, object $grantee): void
    {
        $this->permission = $permission;
        $this->grantee    = $grantee;
    }

    /**
     * Return the grantee whose permission of the name matched the action; null
     * when none of that name did.
     *
     * @param  string  $permission
     * @return object|null
     */
    public function granteeOf(string $permission): ?object
    {
        return $this->permission === $permission ? $this->grantee : null;
    }
}
