<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Resolvers;

use SineMacula\Laravel\Authorization\Contracts\AuthorizableIdentity;
use SineMacula\Laravel\Authorization\Contracts\PolicyResolver;
use SineMacula\Laravel\Authorization\Contracts\PolicyStore;
use SineMacula\Laravel\Authorization\Evaluation\EvidenceRecorder;

/**
 * Default policy resolver.
 *
 * Unions the policies returned by an optional external `PolicyStore`, asked on
 * every check, such as policies shipped in code, with the policies attached to
 * the principal itself when it is an `AuthorizableIdentity`, which
 * `getPolicies()` reads through the resolution cache: its own attachments,
 * inline policies included, and the policies attached to the roles it holds and
 * to the roles above them, each where both grants hold (AUTHZ-6.9, AUTHZ-7.2).
 * A principal that implements neither contract contributes no policies of its
 * own. The evaluator still weighs the identity's and the resource's policies,
 * the guardrails, the boundaries and the session caps. A permission the subject
 * holds then allows only at the allow stage, after every deny and cap, and only
 * where the grant it came from reaches the check; otherwise the check is an
 * implicit deny.
 *
 * The order of the list never matters: the evaluator assesses the policies by
 * name, then stored key, then document, wherever they came from.
 *
 * For an explained check (N89), `explainedPoliciesFor()` resolves the same
 * policies, noting where each came from: the store's as `unavailable`, since a
 * store cannot say, and the principal's own through the grant rows that gave
 * them (see `GrantProvenanceResolver`).
 *
 * The resolver is intentionally stateless so consumers can decorate it with
 * cache or tenant-scoping layers without inheriting any internal state.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class DefaultPolicyResolver implements PolicyResolver
{
    /**
     * Create a new resolver instance.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\PolicyStore|null  $store
     */
    public function __construct(

        /** Optional external policy source unioned with the principal's own. */
        private ?PolicyStore $store = null,
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

    /**
     * Return every policy applicable to the principal, as `policiesFor()` does,
     * for an explained check, noting with the recorder where each came from:
     * the store's policies as `unavailable`, and the principal's own by the
     * grant rows that gave them.
     *
     * @param  object  $principal
     * @param  \SineMacula\Laravel\Authorization\Evaluation\EvidenceRecorder  $recorder
     * @return array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>
     *
     * @throws \SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\RoleHierarchyCycleException
     *
     * @internal
     */
    public function explainedPoliciesFor(object $principal, EvidenceRecorder $recorder): array
    {
        $policies = $this->store?->policiesFor($principal) ?? [];

        $recorder->notePolicies($policies, null);

        if ($principal instanceof AuthorizableIdentity) {
            $policies = \array_merge($policies, GrantProvenanceResolver::policiesOf($principal, $recorder));
        }

        return \array_values($policies);
    }
}
