<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

use SineMacula\Laravel\Authorization\Contracts\PolicyResolver;
use SineMacula\Laravel\Authorization\Resolvers\DefaultPolicyResolver;
use SineMacula\Laravel\Authorization\Resolvers\GrantProvenanceResolver;
use SineMacula\Laravel\Authorization\Resolvers\ResourcePolicyResolver;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use SineMacula\Laravel\Authorization\Support\SubjectGrants;
use SineMacula\Laravel\Authorization\Usage\WeighedGrants;

/**
 * Gathers what a check's grants give for `DecisionPipeline`: the policies of
 * the subject, its identity and the resource, and the permission held.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CheckGrants
{
    /**
     * Create a new check grants instance.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\PolicyResolver  $policyResolver
     * @param  \SineMacula\Laravel\Authorization\Resolvers\ResourcePolicyResolver|null  $resourcePolicies
     */
    public function __construct(

        /** Gathers the policy set applicable to a principal per check. */
        private PolicyResolver $policyResolver,

        /** Reads the policies attached to a check's resource and its type; null reads none. */
        private ?ResourcePolicyResolver $resourcePolicies,
    ) {}

    /**
     * Return the permission held, as a callback the allow stage asks: explained
     * with where it came from given a recorder, noted on what a tracked check
     * weighed given that, and noted with the break-glass activations behind it
     * while they count.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  string  $action
     * @param  \SineMacula\Laravel\Authorization\Evaluation\EvidenceRecorder|null  $evidence
     * @param  \SineMacula\Laravel\Authorization\Usage\WeighedGrants|null  $weighed
     * @param  \SineMacula\Laravel\Authorization\Evaluation\BreakGlassAttribution|null  $attribution
     * @return \Closure(): ?string
     */
    public static function permission(Subject $subject, string $action, ?EvidenceRecorder $evidence, ?WeighedGrants $weighed, ?BreakGlassAttribution $attribution): \Closure
    {
        $held = $evidence === null
            ? static fn (): ?string => SubjectGrants::permissionFor($subject, $action, $weighed)
            : static fn (): ?string => $evidence->notePermission(GrantProvenanceResolver::permissionFor($subject, $action));

        return $attribution === null ? $held : static fn (): ?string => $attribution->notePermission($held());
    }

    /**
     * Gather the policies applicable to the supplied subject and resource.
     *
     * The bound `PolicyResolver` gives the subject's, so consumers swap the
     * resolver to introduce tenant scoping or other gathering strategies
     * without touching the manager; the policies attached to its identity are
     * added when that is another model, whole when it grants to the subject
     * (another model of the same kind, see `SubjectGrants::grantingIdentity()`)
     * and as their deny statements alone otherwise, and those attached to the
     * resource and its type (see `ResourcePolicyResolver`). Given a recorder,
     * the subject's and its identity's policies are resolved with where each
     * came from (see `explained()`).
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference|null  $resource
     * @param  \SineMacula\Laravel\Authorization\Evaluation\EvidenceRecorder|null  $evidence
     * @param  \SineMacula\Laravel\Authorization\Evaluation\BreakGlassAttribution|null  $attribution
     * @return array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>
     *
     * @throws \SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException
     */
    public function policies(Subject $subject, ?ResourceReference $resource, ?EvidenceRecorder $evidence, ?BreakGlassAttribution $attribution): array
    {
        $own = $evidence === null
            ? [...$this->policyResolver->policiesFor($subject->subject), ...SubjectGrants::identityPolicies($subject)]
            : $this->explained($subject, $evidence);

        // Reading the resource's policies in its tenant empties the memo.
        $attribution?->notePolicies();

        return [...$own, ...$this->resourcePolicies?->policiesFor($resource) ?? []];
    }

    /**
     * Gather the subject's and its identity's policies for an explained check,
     * noting where each came from with the recorder: through the default
     * resolver, by the grant rows that gave them, and through a resolver bound
     * in its place, which cannot say, as `unavailable`.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  \SineMacula\Laravel\Authorization\Evaluation\EvidenceRecorder  $evidence
     * @return array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>
     *
     * @throws \SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException
     */
    private function explained(Subject $subject, EvidenceRecorder $evidence): array
    {
        if ($this->policyResolver instanceof DefaultPolicyResolver) {
            $principal = $this->policyResolver->explainedPoliciesFor($subject->subject, $evidence);
        } else {
            $principal = $this->policyResolver->policiesFor($subject->subject);

            $evidence->notePolicies($principal, null, $subject->subject);
        }

        return [...$principal, ...GrantProvenanceResolver::identityPolicies($subject, $evidence)];
    }
}
