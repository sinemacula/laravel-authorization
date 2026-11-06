<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Events\Resource;

/**
 * Dispatched when a policy is attached to a resource, a record or a whole
 * resource type (AUTHZ-7.3), or an attachment of it changes its reach.
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
final readonly class PolicyAttached extends ResourcePolicyEvent {}
