<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events\Resource;

use SineMacula\Laravel\Authorization\Enums\MutationOperation;

/**
 * Dispatched when a policy is detached from a resource, a record or a whole
 * resource type (AUTHZ-7.3), in one scope.
 *
 * It carries what every change to an attachment does (see
 * `ResourcePolicyEvent`): the operation, the resource's type and key (null for
 * the whole type), the policy, its name and the scope.
 *
 * Part of the SemVer-stable event API; breaking changes require a major version
 * bump.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PolicyDetached extends ResourcePolicyEvent
{
    /**
     * Return the stable identifier of the change: `resource.policy.detached`.
     *
     * @return string
     */
    #[\Override]
    public function operation(): string
    {
        return MutationOperation::RESOURCE_POLICY_DETACHED->value;
    }
}
