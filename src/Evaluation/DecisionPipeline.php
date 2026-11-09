<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Evaluation;

use SineMacula\Laravel\Authorization\Administration\FurtherChecks;
use SineMacula\Laravel\Authorization\Administration\OperationConstraints;
use SineMacula\Laravel\Authorization\Administration\OperationResource;
use SineMacula\Laravel\Authorization\Context\AttributeNamespaces;
use SineMacula\Laravel\Authorization\Context\CheckContextFactory;
use SineMacula\Laravel\Authorization\Context\ResourceAttributeBatch;
use SineMacula\Laravel\Authorization\Contracts\PolicyResolver;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Preview\Previewing;
use SineMacula\Laravel\Authorization\Query\QueryAuthorizer;
use SineMacula\Laravel\Authorization\Resolvers\DefaultPolicyResolver;
use SineMacula\Laravel\Authorization\Resolvers\GrantProvenanceResolver;
use SineMacula\Laravel\Authorization\Resolvers\GuardrailResolver;
use SineMacula\Laravel\Authorization\Resolvers\ResourcePolicyResolver;
use SineMacula\Laravel\Authorization\Resolvers\SessionCapResolver;
use SineMacula\Laravel\Authorization\Reviews\ReviewAdmission;
use SineMacula\Laravel\Authorization\Reviews\ReviewResource;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use SineMacula\Laravel\Authorization\Support\ResourceScope;
use SineMacula\Laravel\Authorization\Support\SubjectGrants;

/**
 * Decides a check for the authorization manager, stage by stage (AUTHZ-7.1).
 *
 * The pipeline admits the check (the subject, resource and tenant stages) and
 * gathers every source, the session caps included; the policy evaluator runs
 * the rest of the stages, the denies, the caps, the allows and the implicit
 * deny, each recorded in the decision's trace. It records nothing and reports
 * nothing: the manager's `check()` is the one decision entry point (D22), and
 * `checkMany()` the same over many checks, and `CheckBatch` owns the recording
 * for both, so every decision the pipeline makes reaches the caller through it.
 *
 * A pipeline is immutable: `withPolicies()`, `capped()`, `withoutSessionCaps()`
 * and `explaining()` return a new one, as the manager's scoped clones do.
 *
 * A pipeline `explaining()` returns decides its one check in explain mode
 * (N89): exactly as any other, through the same stages and the same sources,
 * recording besides the evidence an explanation needs, where each grant that
 * allowed it came from, read by the grant resolution itself (see
 * `GrantProvenanceResolver`), and each condition test with what it found (see
 * `CheckContext::explain()`), and returning the decision with it (see
 * `DecisionEvidence`). Every other pipeline records none, and costs what it did
 * before explanations.
 *
 * A bulk check decides each of its checks through `decide()` too, exactly as a
 * single check is decided; `prepare()` only reads ahead, in bulk, what those
 * checks will read, and a check of the batch reads its resource's attributes
 * through the batch's (see `ResourceAttributeBatch`), so the decisions are the
 * ones the checks would get one at a time.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class DecisionPipeline
{
    /** @var array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>|null Per-call policy override supplied via `withPolicies()`. */
    private ?array $policyOverride = null;

    /** @var list<list<string>> The explicit session caps supplied via `capped()`, outermost first, every one of which must cover the action. */
    private array $caps = [];

    /** @var bool Whether checks are decided as for a principal holding no session yet: no credential's scopes are read, and a machine is not capped for lacking them. */
    private bool $isSessionless = false;

    /** @var \SineMacula\Laravel\Authorization\Evaluation\EvidenceRecorder|null Records the evidence of the one check an `explaining()` pipeline decides; null for every other pipeline. */
    private ?EvidenceRecorder $evidence = null;

    /**
     * Create a new decision pipeline instance.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\PolicyEvaluator  $evaluator
     * @param  \SineMacula\Laravel\Authorization\Contracts\PolicyResolver  $policyResolver
     * @param  \SineMacula\Laravel\Authorization\Context\CheckContextFactory|null  $contexts
     * @param  \SineMacula\Laravel\Authorization\Resolvers\ResourcePolicyResolver|null  $resourcePolicies
     * @param  \SineMacula\Laravel\Authorization\Resolvers\GuardrailResolver|null  $guardrails
     * @param  \SineMacula\Laravel\Authorization\Resolvers\SessionCapResolver|null  $sessionCaps
     */
    public function __construct(

        /** Policy evaluator used to walk statements for every check. */
        private readonly PolicyEvaluator $evaluator,

        /** Gathers the policy set applicable to a principal per check. */
        private readonly PolicyResolver $policyResolver,

        /** Makes each check's context from its sources; null gives a check only what the caller passes, under `input`. */
        private readonly ?CheckContextFactory $contexts = null,

        /** Reads the policies attached to a check's resource and its type; null reads none. */
        private readonly ?ResourcePolicyResolver $resourcePolicies = null,

        /** Reads the guardrails that apply to a check; null reads none. */
        private readonly ?GuardrailResolver $guardrails = null,

        /** Makes the session caps of a check; null reads no credential's scopes, so only `capped()` and a machine's missing scopes cap it. */
        private readonly ?SessionCapResolver $sessionCaps = null,
    ) {}

    /**
     * Return a pipeline that evaluates only the supplied policies, bypassing
     * the principal's own attached policies, any configured policy store and
     * the policies attached to the resource. The guardrails, the subject's
     * permission boundaries, the session caps and its permissions still count.
     *
     * @param  array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>  $policies
     * @return self
     */
    public function withPolicies(array $policies): self
    {
        $pipeline                 = clone $this;
        $pipeline->policyOverride = $policies;

        return $pipeline;
    }

    /**
     * Determine whether the pipeline evaluates only the policies
     * `withPolicies()` supplied, in place of the stored ones.
     *
     * @return bool
     */
    public function hasPolicyOverride(): bool
    {
        return $this->policyOverride !== null;
    }

    /**
     * Return a pipeline whose checks are also capped by the supplied actions,
     * each an action or an action pattern, intersected with the caps already in
     * place.
     *
     * @param  list<string>  $actions
     * @return self
     */
    public function capped(array $actions): self
    {
        $pipeline         = clone $this;
        $pipeline->caps[] = $actions;

        return $pipeline;
    }

    /**
     * Return a pipeline whose checks are decided as for a principal that holds
     * no session yet (N105): the session policy source is not asked for the
     * subject's credential scopes, so neither a credential's scopes nor a
     * machine's missing ones cap a check, while the explicit caps of `capped()`
     * still do. Every other stage, the denies, guardrails and boundaries among
     * them, decides as for any check.
     *
     * @return self
     */
    public function withoutSessionCaps(): self
    {
        $pipeline                = clone $this;
        $pipeline->isSessionless = true;

        return $pipeline;
    }

    /**
     * Determine whether the pipeline decides its checks as for a principal that
     * holds no session yet, as `withoutSessionCaps()` returned it.
     *
     * @return bool
     */
    public function isSessionless(): bool
    {
        return $this->isSessionless;
    }

    /**
     * Return a pipeline that decides one check in explain mode, recording the
     * evidence an explanation needs beside its decision; a pipeline for each
     * explained check, since it records that check's evidence alone.
     *
     * @return self
     */
    public function explaining(): self
    {
        $pipeline           = clone $this;
        $pipeline->evidence = new EvidenceRecorder;

        return $pipeline;
    }

    /**
     * Decide the action for the supplied subject, stage by stage (AUTHZ-7.1),
     * admitting the check first: a subject that is missing, or inactive (it or
     * its identity), is denied before anything else is read; a resource that
     * cannot be identified is denied next; a tenant-owned resource is decided
     * in its tenant's scope, or denied as out of scope (see `ResourceScope`);
     * then the grants decide. A check of a bulk check reads its resource's
     * attributes through the batch's.
     *
     * A witness given is called in the scope the grants are weighed in, just
     * before they are, so the caller can read where the check was decided: the
     * resource's tenant, platform scope, or the scope in place. It is not
     * called for a check denied before then, by the subject, resource or tenant
     * stage, which is decided in the scope in place.
     *
     * A pipeline `explaining()` returned returns the decision with the evidence
     * its check recorded, an early refusal's included.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject|null  $subject
     * @param  string  $action
     * @param  false|\SineMacula\Laravel\Authorization\Support\ResourceReference|null  $resource
     * @param  array<string, mixed>  $context
     * @param  \SineMacula\Laravel\Authorization\Context\ResourceAttributeBatch|null  $attributes
     * @param  (\Closure(): void)|null  $witness
     * @return \SineMacula\Laravel\Authorization\Evaluation\Decision
     */
    public function decide(
        ?Subject $subject,
        string $action,
        false|ResourceReference|null $resource,
        array $context,
        ?ResourceAttributeBatch $attributes = null,
        ?\Closure $witness = null,
    ): Decision {
        $decision = $this->runStages($subject, $action, $resource, $context, $attributes, $witness);

        return $this->evidence === null ? $decision : $decision->withEvidence($this->evidence->evidenceFor($decision));
    }

    /**
     * Read ahead, in bulk, what checks on the resources will read, for the
     * subject: the policies attached to each record and to its type, in the
     * scope each record's check is decided in (see `ResourceScope`), through
     * the resolution cache, which keeps each record's, so each check then reads
     * its own from there, or afresh after a write. Nothing is decided, so a
     * check reads exactly what it would have read without it. Nothing is read
     * for no subject, or an inactive one, whose checks read none, nor under a
     * `withPolicies()` override, which replaces the attached policies; a record
     * whose identifier is not UTF-8 is left to its own check, so a database
     * that refuses it fails that check alone, and whatever cannot be read
     * ahead, a document that cannot be read or a tenant whose place in the tree
     * cannot be read say, is left to each check that reads it, so a failure
     * here never stops a check that would not fail on its own.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject|null  $subject
     * @param  array<array-key, mixed>  $resources
     * @return void
     *
     * @internal
     */
    public function prepare(?Subject $subject, array $resources): void
    {
        $policies = $this->policyOverride === null ? $this->resourcePolicies : null;

        if ($policies === null || $subject === null || SubjectGrants::isInactive($subject)) {
            return;
        }

        $records = [];

        foreach ($resources as $key => $resource) {
            if (!$resource instanceof ResourceReference || $resource->id === null || !\mb_check_encoding($resource->identifier, 'UTF-8')) {
                continue;
            }

            $records[$key] = $resource;
        }

        // A group that cannot be read ahead, a document that cannot be read
        // among it say, is read again by each of its checks, which decides or
        // fails alone (see `ResourceScope::prepare()`).
        ResourceScope::prepare($records, static fn (array $group): array => $policies->policiesForMany($group));
    }

    /**
     * Gather every source the check is decided from, in the scope it runs in:
     * the policies, the guardrails (none when the check is exempt from them),
     * the boundaries, the check's context, the permission held and the session
     * caps, as `decideGrants()` weighs them. `whereAuthorized()` reads them
     * before they are weighed, so a query is decided from exactly the sources
     * `check()` is. A check of a bulk check reads its resource's attributes
     * through the batch's. The subject a running use of a preview decides about
     * is first admitted in the scope in place, where its sources are gathered
     * (see `Preview\Previewing::admit()`), so a decision about a preview's
     * target is never made where its previewer may not preview.
     *
     * Given a recorder, the check is explained: the policies and the permission
     * held are resolved with where each came from, noted with the recorder, and
     * the context records each condition test (N89).
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  string  $action
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference|null  $resource
     * @param  array<string, mixed>  $context
     * @param  \SineMacula\Laravel\Authorization\Context\ResourceAttributeBatch|null  $attributes
     * @param  \SineMacula\Laravel\Authorization\Evaluation\EvidenceRecorder|null  $evidence
     * @return \SineMacula\Laravel\Authorization\Evaluation\CheckSources
     *
     * @throws \SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException
     *
     * @internal
     */
    public function sources(
        Subject $subject,
        string $action,
        ?ResourceReference $resource,
        array $context,
        ?ResourceAttributeBatch $attributes = null,
        ?EvidenceRecorder $evidence = null,
    ): CheckSources {
        // The subject of a preview's use is admitted where its sources are
        // gathered, before any is read (see `Preview\PreviewAdmission`).
        Previewing::admit($subject);

        $policies   = $this->gatherPolicies($subject, $resource, $evidence);
        $guardrails = $action === PackagePermissions::GUARDRAIL_MANAGE ? null : ($this->guardrails?->guardrailsFor($resource) ?? []);
        $boundaries = SubjectGrants::boundaries($subject);

        // What the caller passes is held under `input` alone, never promoted
        // into another namespace, so it cannot stand in for the request, the
        // authentication, the subject, the resource or any source's values
        // (N27). Without a factory, the subject and resource still supply their
        // built-in keys.
        $checkContext = $this->contexts?->make($context, $subject, $resource, $attributes)
            ?? new CheckContext([CheckContextFactory::INPUT => $context], (new AttributeNamespaces)->builders($subject, $resource), null, new PrincipalSelectors($subject));

        $permission = $evidence === null
            ? static fn (): ?string => SubjectGrants::permissionFor($subject, $action)
            : static fn (): ?string => $evidence->notePermission(GrantProvenanceResolver::permissionFor($subject, $action));
        $session = $this->isSessionless
            ? SessionCaps::of(null, $this->caps)
            : ($this->sessionCaps ?? new SessionCapResolver)->capsFor($subject, $this->caps);

        if ($evidence !== null) {
            $checkContext->explain();
        }

        return new CheckSources($policies, $guardrails, $boundaries, $checkContext, $permission, $session);
    }

    /**
     * Weigh the sources gathered for a check, stage by stage, through the
     * policy evaluator.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\CheckSources  $sources
     * @param  string  $action
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference|null  $resource
     * @return \SineMacula\Laravel\Authorization\Evaluation\Decision
     *
     * @internal
     */
    public function weigh(CheckSources $sources, string $action, ?ResourceReference $resource): Decision
    {
        $evaluator = $this->evaluator->capped($sources->session);

        return $evaluator->evaluate($sources->policies, $action, $resource?->identifier, $sources->context, $sources->boundaries, $sources->permission, $sources->guardrails);
    }

    /**
     * Return the compiler that scopes a query to the records this pipeline
     * would allow (AUTHZ-10.1), with this pipeline's sources: its context
     * factory, its guardrails, which it reads for the tenant chain of a record
     * admitted from outside the scope, and, unless a `withPolicies()` override
     * replaces them, its resource policies, whose record attachments it must
     * see.
     *
     * @return \SineMacula\Laravel\Authorization\Query\QueryAuthorizer
     *
     * @internal
     */
    public function queryAuthorizer(): QueryAuthorizer
    {
        return new QueryAuthorizer($this, $this->contexts, $this->policyOverride === null ? $this->resourcePolicies : null, $this->guardrails);
    }

    /**
     * Admit the check, and decide it from the grants once it is admitted (see
     * `decide()`).
     *
     * @param  \SineMacula\Laravel\Authorization\Subject|null  $subject
     * @param  string  $action
     * @param  false|\SineMacula\Laravel\Authorization\Support\ResourceReference|null  $resource
     * @param  array<string, mixed>  $context
     * @param  \SineMacula\Laravel\Authorization\Context\ResourceAttributeBatch|null  $attributes
     * @param  (\Closure(): void)|null  $witness
     * @return \SineMacula\Laravel\Authorization\Evaluation\Decision
     */
    private function runStages(
        ?Subject $subject,
        string $action,
        false|ResourceReference|null $resource,
        array $context,
        ?ResourceAttributeBatch $attributes,
        ?\Closure $witness,
    ): Decision {
        if ($subject === null || SubjectGrants::isInactive($subject)) {
            return Decision::deny($subject === null ? DecisionReason::SUBJECT_UNRESOLVED : DecisionReason::SUBJECT_INACTIVE, DecisionStage::SUBJECT);
        }

        if ($resource === false) {
            return Decision::deny(DecisionReason::RESOURCE_UNRESOLVED, DecisionStage::RESOURCE);
        }

        $here   = $resource?->source instanceof OperationResource ? TenantScope::currentTenant() : null;
        $from   = $here === null ? null : new Reference($here[0], $here[1]);
        $decide = function () use ($subject, $action, $resource, $context, $attributes, $from, $witness): Decision {
            if ($witness !== null) {
                $witness();
            }

            return $this->decideGrants($subject, $action, $resource, $context, $attributes, $from);
        };

        return $resource === null ? $decide() : ResourceScope::decide($subject, $action, $resource, $decide);
    }

    /**
     * Decide the admitted action from every source the subject's grants and the
     * resource give, in the evaluator's stages: every explicit deny, from the
     * subject's policies, its identity's, those attached to the resource and
     * its type, the guardrails and its boundaries; then the caps, the
     * guardrails of the check's tenant, its ancestors and the platform, then
     * the boundaries of the subject and its identity; then every allow, a
     * policy's, a resource policy's naming the subject, and a permission the
     * subject holds; then the implicit deny. No allow is weighed before every
     * deny and cap, so a guardrail, a boundary or a session cap caps a resource
     * policy's allow and a permission held as it caps a policy's. A permission
     * held is asked for at the allow stage alone (AUTHZ-7.7), and its step
     * names the permission that allowed. It counts only when the grant it came
     * from reaches the check: the permissions are resolved in the scope the
     * check is decided in (see `ResourceScope`): for a resource within the
     * active tenant's subtree, its own tenant, so a grant there, an ancestor's
     * grant that reaches its subtree, or a platform-wide grant; for a resource
     * admitted from outside the scope, platform scope, so only a platform-wide
     * grant; for a resource with no tenant, a type alone, an opaque identifier
     * or no resource, the grants that hold in the active tenant, or only
     * platform-wide ones with none. A grant for another application, or one
     * that has expired, never counts. The session caps are the scopes of the
     * subject's credential, mapped to actions, and those `capped()` supplied,
     * every one of which must cover the action (see `SessionCapResolver`); a
     * machine without credential scopes is allowed nothing.
     *
     * The guardrails are those of the resource's tenant when it has one, also
     * when a platform-wide grant admitted it from outside the scope, else of
     * the tenant the check is decided in (see `GuardrailResolver`). A check of
     * exactly `authorization:guardrail.manage` is exempt from them: no
     * guardrail is read for it, so none of their denies or allows applies, nor
     * does one that cannot be read, and the guardrail stage records it as
     * exempt. A guardrail therefore never keeps anyone from changing the
     * guardrails, its own removal included; every other deny and cap still
     * applies, and the guardrail service still asks for the right from above
     * the scope it changes (see `GuardrailAuthority`).
     *
     * A resource policy's denies apply to everyone, and its allows to the
     * subjects their `principals` name, with no permission held; by now the
     * tenant stage has admitted the resource, so a resource policy never allows
     * across tenants, and a deny attached to the resource in its own tenant
     * applies even once the check falls back to platform scope. A policy,
     * guardrail or boundary document that cannot be read denies the check as an
     * invalid policy. The subject's identity, when it is another model of the
     * same kind (both machines or neither, see
     * `SubjectGrants::grantingIdentity()`), contributes its policies and its
     * grants; its deny statements and its boundaries cap the check whatever its
     * kind. A `withPolicies()` override replaces the policies alone: the
     * guardrails, the subject's boundaries, the session caps and its
     * permissions still count.
     *
     * An allow of an administration action on an operation resource of that
     * action then passes the operation's constraints, at the administration
     * stage, which can only refuse it (see `OperationConstraints`); a further
     * check they need is decided here, as this one is up to the allow, in the
     * scope in place when they ask, and never through the administration stage
     * again; the stage also learns the tenant the check was made from, before
     * the operation's own tenant was put in place. An allow of a review right
     * on a review resource passes the review's reach there in the same way (see
     * `Reviews\ReviewAdmission`), which can only refuse it.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  string  $action
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference|null  $resource
     * @param  array<string, mixed>  $context
     * @param  \SineMacula\Laravel\Authorization\Context\ResourceAttributeBatch|null  $attributes
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $from
     * @return \SineMacula\Laravel\Authorization\Evaluation\Decision
     */
    private function decideGrants(
        Subject $subject,
        string $action,
        ?ResourceReference $resource,
        array $context,
        ?ResourceAttributeBatch $attributes,
        ?Reference $from = null,
    ): Decision {
        $decision = $this->decideAlone($subject, $action, $resource, $context, $attributes, $this->evidence);

        $source = $resource?->source;

        if ($source instanceof ReviewResource) {
            return ReviewAdmission::weigh($decision, $action, $resource, $this->furtherChecks($subject, $context, $attributes, $from));
        }

        return $source instanceof OperationResource
            ? OperationConstraints::weigh($decision, $action, $resource, $this->furtherChecks($subject, $context, $attributes, $from))
            : $decision;
    }

    /**
     * Return the further checks the administration stage may need for the
     * subject, each decided as `decideGrants()` decides its own check up to the
     * allow, in the scope in place when it is asked.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  array<string, mixed>  $context
     * @param  \SineMacula\Laravel\Authorization\Context\ResourceAttributeBatch|null  $attributes
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $from
     * @return \SineMacula\Laravel\Authorization\Administration\FurtherChecks
     */
    private function furtherChecks(Subject $subject, array $context, ?ResourceAttributeBatch $attributes, ?Reference $from): FurtherChecks
    {
        return new FurtherChecks(
            $subject,
            fn (string $further, ?ResourceReference $on): Decision => $this->decideAlone($subject, $further, $on, $context, $attributes),
            fn (string $further): ?CheckSources => $this->sourcesOrNone($subject, $further, $context),
            $from,
        );
    }

    /**
     * Gather the sources of a check of the action on no resource, in the scope
     * in place, or none when a document among them cannot be read.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  string  $action
     * @param  array<string, mixed>  $context
     * @return \SineMacula\Laravel\Authorization\Evaluation\CheckSources|null
     */
    private function sourcesOrNone(Subject $subject, string $action, array $context): ?CheckSources
    {
        try {
            return $this->sources($subject, $action, null, $context);
        } catch (InvalidPolicyDocumentException) {
            return null;
        }
    }

    /**
     * Decide the admitted action from every source, up to the allow, in the
     * scope in place, without the administration stage: a document that cannot
     * be read denies it as an invalid policy. Given a recorder, the check is
     * explained (see `sources()`); a further check the administration stage
     * makes never is.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  string  $action
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference|null  $resource
     * @param  array<string, mixed>  $context
     * @param  \SineMacula\Laravel\Authorization\Context\ResourceAttributeBatch|null  $attributes
     * @param  \SineMacula\Laravel\Authorization\Evaluation\EvidenceRecorder|null  $evidence
     * @return \SineMacula\Laravel\Authorization\Evaluation\Decision
     */
    private function decideAlone(
        Subject $subject,
        string $action,
        ?ResourceReference $resource,
        array $context,
        ?ResourceAttributeBatch $attributes,
        ?EvidenceRecorder $evidence = null,
    ): Decision {
        try {
            $sources = $this->sources($subject, $action, $resource, $context, $attributes, $evidence);
        } catch (InvalidPolicyDocumentException) {
            return Decision::deny(DecisionReason::INVALID_POLICY, DecisionStage::DENY);
        }

        return $this->weigh($sources, $action, $resource);
    }

    /**
     * Gather the policies applicable to the supplied subject and resource.
     *
     * When a per-call override is in effect, it is returned verbatim. Otherwise
     * the pipeline delegates to the bound `PolicyResolver` for the subject —
     * consumers swap the resolver to introduce tenant scoping or other
     * gathering strategies without touching the manager — and adds the policies
     * attached to its identity when that is another model, whole when it grants
     * to the subject (another model of the same kind, see
     * `SubjectGrants::grantingIdentity()`) and as their deny statements alone
     * otherwise, and those attached to the resource and its type (see
     * `ResourcePolicyResolver`). Given a recorder, the subject's and its
     * identity's policies are resolved with where each came from (see
     * `explainedPolicies()`).
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference|null  $resource
     * @param  \SineMacula\Laravel\Authorization\Evaluation\EvidenceRecorder|null  $evidence
     * @return array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>
     *
     * @throws \SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException
     */
    private function gatherPolicies(Subject $subject, ?ResourceReference $resource, ?EvidenceRecorder $evidence): array
    {
        if ($this->policyOverride !== null) {
            return $this->policyOverride;
        }

        $own = $evidence === null
            ? [...$this->policyResolver->policiesFor($subject->subject), ...SubjectGrants::identityPolicies($subject)]
            : $this->explainedPolicies($subject, $evidence);

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
    private function explainedPolicies(Subject $subject, EvidenceRecorder $evidence): array
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
