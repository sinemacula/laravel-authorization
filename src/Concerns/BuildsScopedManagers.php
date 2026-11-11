<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Concerns;

use SineMacula\Laravel\Authorization\Exceptions\InvalidPreviewException;
use SineMacula\Laravel\Authorization\Preview\PreviewContext;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\AuthorizationScope;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * The scoped clones of the authorization manager: `for()` and `forUser()`,
 * which name the subject its checks are about, `for()` deciding in the tenant
 * and application a `Subject` names (N109), or on the platform for a `Subject`
 * it is given carrying the platform marker (N120), `forActor()`, which names an
 * acting subject decided in the scope in place, `previewFor()`, which previews
 * another subject as the caller, and `withPolicies()`, `capped()` and
 * `withoutSessionCaps()`, which change how they are decided. Each returns a
 * clone, so the manager it is called on is unchanged.
 *
 * A preview keeps its two parties and its scope (see `PreviewContext`): on a
 * preview, `for()`, `forActor()`, `forUser()` and `previewFor()`, which would
 * change its target, and `withPolicies()`, which would decide through
 * hypothetical policies, and `withoutSessionCaps()`, which would lift the
 * target's credential caps, throw `InvalidPreviewException`, while `capped()`
 * caps the target's checks alone, never the previewer's admission. A manager
 * carrying a policy override, or built by `withoutSessionCaps()`, cannot be
 * previewed from, so a preview never decides through hypothetical policies or
 * without session caps, for either party.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait BuildsScopedManagers
{
    /** @var \SineMacula\Laravel\Authorization\Subject|null The subject named through `for()` or `forUser()`, null for a guest. */
    private ?Subject $subjectOverride = null;

    /** @var bool Whether `for()` or `forUser()` named the subject; until one does, the bound resolver resolves it. */
    private bool $isSubjectNamed = false;

    /** @var \SineMacula\Laravel\Authorization\Subject|null The `Subject` named through `for()`, whose tenant, or the platform for one carrying the marker, and application, read at each decision, its checks are decided in, or null to decide in the scope in place. */
    private ?Subject $scopeSubject = null;

    /** @var \SineMacula\Laravel\Authorization\Preview\PreviewContext|null Who previews whom, and where, for a preview from `previewFor()`; null for any other manager. */
    private ?PreviewContext $preview = null;

    /**
     * Return a scoped manager deciding about the supplied subject.
     *
     * A resolved `Subject` is taken as it is, its identity, guard and session
     * kept, as an acting context names its actor (see
     * `Administration\ActingContext`). When it names a tenant or an
     * application, every check of the manager is decided there (N109): its
     * tenant, or the platform for none, and its application, or none, are put
     * in place of the request's, both as the ambient grant scope and as the
     * subject's, for each check, batch, explanation and compile of a query
     * scoped through it, and the request's are restored afterwards, even when
     * the check throws (see `AuthorizationScope::within()`), held there for the
     * whole check or batch, even when it is the request's and the decisions of
     * the request are forgotten meanwhile (see `forgetDecisionsFor()`). That is
     * the decision `AuthorizationScope::within()` around `for()` of the subject
     * in that scope makes, so wrapping the call still gives the same result. A
     * `Subject` carrying the platform marker (N120) is decided on the platform
     * the same way, with no tenant, on its application, or on none, whatever
     * tenant the request or an explicit `AuthorizationScope::within()` has put
     * in place. A `Subject` naming none of them is decided in the scope in
     * place. Any other model is named in the request's tenant, application,
     * guard and platform marker, and is decided in the scope in place, whatever
     * marker it carries: on the platform for a request whose subject is on the
     * platform and names no tenant, while no other scope is in place, and in
     * the tenant an explicit `AuthorizationScope::within()` puts in place; with
     * no subject resolved, it has none. The subject's tenant is read when a
     * check is decided, not here, so a tenant that cannot be read throws
     * `InvalidTenantException` from the check, before anything is decided, as
     * it did before the subject's scope was put in place.
     *
     * @param  object  $subject
     * @return self
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidPreviewException
     */
    public function for(object $subject): self
    {
        $this->state?->ensureHealthy();

        $this->refuseOnPreview('for');

        if (!$subject instanceof Subject) {
            return $this->scopedTo($this->currentSubject()?->withSubject($subject) ?? new Subject($subject, $subject));
        }

        $scoped               = $this->scopedTo($subject);
        $scoped->scopeSubject = $subject;

        return $scoped;
    }

    /**
     * Return a scoped manager deciding about the acting subject in the tenant
     * and application in place, whatever the subject names, its tenant, its
     * application and its platform marker (N120) included, as `for()` of a
     * model and `forUser()` do, and unlike `for()` of a `Subject`: what
     * delegated administration and access reviews decide an actor's rights
     * through, in the reach they put in place (see
     * `Administration\ActingContext`).
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return self
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidPreviewException
     *
     * @internal
     */
    public function forActor(Subject $subject): self
    {
        $this->state?->ensureHealthy();

        $this->refuseOnPreview('forActor');

        return $this->scopedTo($subject);
    }

    /**
     * Return a scoped manager deciding about the subject the resolver
     * translates the supplied user into: the user Laravel's Gate hands over,
     * for example, decided in the scope in place, as `for()` decides a model,
     * whatever the subject names, its platform marker (N120) included: a
     * request whose subject is on the platform and names no tenant is decided
     * on the platform while no other scope is in place, and in the tenant an
     * explicit `AuthorizationScope::within()` puts in place, as the Gate,
     * `@can`, `can:` and application access, which decide through it, are. A
     * guest (no user) is no subject, so every check of the scoped manager
     * denies as `subject_unresolved`, whoever the current request is about.
     *
     * @param  object|null  $user
     * @return self
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidPreviewException
     */
    public function forUser(?object $user): self
    {
        $this->state?->ensureHealthy();

        $this->refuseOnPreview('forUser');

        return $this->scopedTo($user === null ? null : $this->subjectResolver->forUser($user));
    }

    /**
     * Return a scoped manager that evaluates only the supplied policies,
     * bypassing the principal's own attached policies, any configured policy
     * store and the policies attached to the resource. A supplied policy given
     * a resource (`Policy::withResource()`) is evaluated as a resource policy.
     * The guardrails, the subject's permission boundaries, the session caps and
     * its permissions still count, so an override never lifts a cap.
     *
     * @param  array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>  $policies
     * @return self
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidPreviewException
     */
    public function withPolicies(array $policies): self
    {
        $this->state?->ensureHealthy();

        if ($this->preview !== null) {
            throw InvalidPreviewException::hypothetical();
        }

        $scoped           = clone $this;
        $scoped->pipeline = $this->pipeline->withPolicies($policies);

        return $scoped;
    }

    /**
     * Return a scoped manager previewing the supplied subject as the caller
     * (AUTHZ-11.4): its checks are about the subject, in the scope, while the
     * caller, the subject this manager decides about, stays who is asking.
     *
     * The subject is previewed with no session: a resolved `Subject` keeps its
     * principal and identity, and a model is named as `for()` names it, so no
     * authentication requirement made of it is met, whatever the caller has
     * proved. A null scope is the request's tenant and application, captured
     * now, or the platform, on the subject's application, for a `Subject` given
     * carrying the platform marker (N120); a model is previewed in the
     * request's tenant and application, whatever marker it carries. The caller
     * must be allowed `authorization:subject.preview` on the preview resource
     * naming the subject and the scope (see `Preview\PreviewResource`), decided
     * as an ordinary check about the caller, with its own session, denies,
     * boundaries, guardrails and caps: now, in the scope, and again at every
     * use of the preview, each check, batch, listing and compile of a query
     * scoped through it, in the scope and in every other scope one of its
     * decisions is made in, a resource's own tenant, the tenants below it or
     * the platform (see `Preview\PreviewAdmission`), so a revocation is seen at
     * the next use. A refusal throws `AuthorizationException` before anything
     * about the subject is decided there.
     *
     * `check()`, `can()`, `cannot()`, `any()`, `all()`, `authorize()`,
     * `explain()`, `checkMany()`, `canEach()`, `filterAuthorized()`,
     * `permissionsFor()` with a null subject, and `whereAuthorized()` given the
     * preview decide about the subject through the one decision path, each
     * decision reported with both parties and every listed action reported too
     * (see `PreviewContext`). Nothing a preview evaluates may change the
     * package's records, and its queries refuse their own writes.
     *
     * @param  object  $subject
     * @param  \SineMacula\Laravel\Authorization\Support\AuthorizationScope|null  $scope
     * @return self
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidPreviewException
     */
    public function previewFor(object $subject, ?AuthorizationScope $scope = null): self
    {
        $this->state?->ensureHealthy();

        $this->refuseOnPreview('previewFor');
        $this->refuseAlteredPipeline();

        $context = PreviewContext::of($this->scopedTo($this->currentSubject()), $subject, $scope);

        // Admitted now, as a use deciding nothing about the target.
        $context->run(static fn (): null => null);

        $preview          = $this->scopedTo($context->target);
        $preview->preview = $context;

        return $preview;
    }

    /**
     * Return a scoped manager whose checks are capped by the supplied actions,
     * each an action or an action pattern, as a delegated or restricted call is
     * (AUTHZ-7.5): an action none of them covers is denied at the session stage
     * as `session_policy`, and an empty list allows nothing.
     *
     * A cap grants nothing, so an action it covers is still decided by every
     * other stage. Capping a capped manager intersects the caps, and the
     * credential's scopes cap the check too. For a machine without credential
     * scopes, which is allowed nothing, a cap never stands in for them. On a
     * preview, the cap applies to the target's checks alone.
     *
     * @param  list<string>  $actions
     * @return self
     */
    public function capped(array $actions): self
    {
        $this->state?->ensureHealthy();

        $scoped           = clone $this;
        $scoped->pipeline = $this->pipeline->capped($actions);

        return $scoped;
    }

    /**
     * Return a scoped manager whose checks are decided as for a principal that
     * holds no session yet (N105), as application admission decides (see
     * `Services\ApplicationAccess`): no credential's scopes cap a check, and a
     * machine is not refused for lacking them, while the explicit caps of
     * `capped()` still apply. The check is otherwise the full decision, through
     * the one decision path, so a deny, a guardrail or a boundary still
     * refuses. Every manager not built through it keeps its session caps.
     *
     * It is for application admission alone: `previewFor()` refuses the manager
     * it returns, so neither a previewer's admission nor a target's checks are
     * decided without session caps, and a preview refuses it.
     *
     * @return self
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidPreviewException
     *
     * @internal
     */
    public function withoutSessionCaps(): self
    {
        $this->state?->ensureHealthy();

        $this->refuseOnPreview('withoutSessionCaps');

        $scoped           = clone $this;
        $scoped->pipeline = $this->pipeline->withoutSessionCaps();

        return $scoped;
    }

    /**
     * Return a clone of this manager deciding about the supplied subject, or
     * about no subject when it is null, in the scope in place.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject|null  $subject
     * @return self
     */
    private function scopedTo(?Subject $subject): self
    {
        $scoped                  = clone $this;
        $scoped->subjectOverride = $subject;
        $scoped->isSubjectNamed  = true;
        $scoped->scopeSubject    = null;

        return $scoped;
    }

    /**
     * Run the callback, a decision about this manager's subject, in the scope
     * of the `Subject` `for()` named, its tenant, or the platform for one
     * carrying the marker, read now, with the request's restored afterwards,
     * even when it throws, or as it is when the subject names no tenant and no
     * application and is not on the platform.
     *
     * @template TResult
     *
     * @param  \Closure(): TResult  $decide
     * @return TResult
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException
     */
    private function inSubjectScope(\Closure $decide): mixed
    {
        $scope = $this->scopeSubject === null ? null : self::scopeOf($this->scopeSubject);

        return $scope === null ? $decide() : $scope->within($decide);
    }

    /**
     * Return the scope a `Subject` names, its tenant, or the platform for none,
     * and its application, or null when it names neither and is not on the
     * platform.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return \SineMacula\Laravel\Authorization\Support\AuthorizationScope|null
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidTenantException
     */
    private static function scopeOf(Subject $subject): ?AuthorizationScope
    {
        if ($subject->tenant === null) {
            return $subject->platform || $subject->application !== null ? AuthorizationScope::platform($subject->application) : null;
        }

        return AuthorizationScope::tenant(new Reference(...TenantScope::extractTenantPair($subject->tenant)), $subject->application);
    }

    /**
     * Refuse a call that would change a preview's target, on a preview.
     *
     * @param  string  $method
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidPreviewException
     */
    private function refuseOnPreview(string $method): void
    {
        if ($this->preview !== null) {
            throw InvalidPreviewException::retargeted($method);
        }
    }

    /**
     * Refuse a preview of a manager that carries a policy override, whose
     * hypothetical policies would stand in for the stored ones, or that decides
     * without session caps, which would admit the caller and decide about the
     * target uncapped.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidPreviewException
     */
    private function refuseAlteredPipeline(): void
    {
        if ($this->pipeline->hasPolicyOverride()) {
            throw InvalidPreviewException::hypothetical();
        }

        if ($this->pipeline->isSessionless()) {
            throw InvalidPreviewException::uncapped();
        }
    }
}
