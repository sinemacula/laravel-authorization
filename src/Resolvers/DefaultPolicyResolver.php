<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Resolvers;

use SineMacula\Laravel\Authorization\Contracts\AuthorizableIdentity;
use SineMacula\Laravel\Authorization\Contracts\PolicyResolver;
use SineMacula\Laravel\Authorization\Contracts\PolicyStore;

/**
 * Default policy resolver.
 *
 * Unions the policies returned by an optional external `PolicyStore` with the
 * policies attached to the principal itself when it is an
 * `AuthorizableIdentity`. A principal that implements neither contract yields
 * an empty policy list — the evaluator then falls through to implicit deny
 * unless an RBAC grant satisfies the check.
 *
 * The resolver is intentionally stateless so consumers can decorate it with
 * cache, tenant-scoping, or role-hierarchy expanders without inheriting any
 * internal state.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class DefaultPolicyResolver implements PolicyResolver
{
    /**
     * Create a new resolver instance.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\PolicyStore|null  $store
     */
    public function __construct(

        /** Optional external policy source unioned with the principal's own. */
        private readonly ?PolicyStore $store = null,

    ) {}

    /**
     * Return every policy applicable to the supplied principal.
     *
     * Unions the optional `PolicyStore`'s contribution with the principal's own
     * attached policies when the principal is an `AuthorizableIdentity`.
     *
     * @param  object  $principal
     * @return array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>
     */
    #[\Override]
    public function policiesFor(object $principal): array
    {
        $policies = [];

        if ($this->store !== null) {
            $policies = $this->store->policiesFor($principal);
        }

        if ($principal instanceof AuthorizableIdentity) {
            $policies = \array_merge($policies, $principal->getPolicies());
        }

        return \array_values($policies);
    }
}
