<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Concerns;

use SineMacula\Laravel\Authorization\Exceptions\InvalidPreviewException;
use SineMacula\Laravel\Authorization\Preview\PreviewContext;
use SineMacula\Laravel\Authorization\Preview\Previewing;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\AuthorizationScope;

/**
 * The scoped clones of the authorization manager: `for()` and `forUser()`,
 * which name the subject its checks are about, `previewFor()`, which previews
 * another subject as the caller, and `withPolicies()` and `capped()`, which
 * change how they are decided. Each returns a clone, so the manager it is
 * called on is unchanged.
 *
 * A preview keeps its two parties and its scope (see `PreviewContext`): on a
 * preview, `for()`, `forUser()` and `previewFor()`, which would change its
 * target, and `withPolicies()`, which would decide through hypothetical
 * policies, throw `InvalidPreviewException`, while `capped()` caps the target's
 * checks alone, never the previewer's admission.
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

    /** @var \SineMacula\Laravel\Authorization\Preview\PreviewContext|null Who previews whom, and where, for a preview from `previewFor()`; null for any other manager. */
    private ?PreviewContext $preview = null;

    /**
     * Return a scoped manager deciding about the supplied subject.
     *
     * The decisions keep the current request's tenant, application and guard,
     * as the resolver reports them; with no subject resolved, they have none. A
     * resolved `Subject` is taken as it is, its identity, guard and session
     * kept, as an acting context names its actor (see
     * `Administration\ActingContext`).
     *
     * @param  object  $subject
     * @return self
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidPreviewException
     */
    public function for(object $subject): self
    {
        $this->refuseOnPreview('for');

        if ($subject instanceof Subject) {
            return $this->scopedTo($subject);
        }

        return $this->scopedTo($this->currentSubject()?->withSubject($subject) ?? new Subject($subject, $subject));
    }

    /**
     * Return a scoped manager deciding about the subject the resolver
     * translates the supplied user into: the user Laravel's Gate hands over,
     * for example. A guest (no user) is no subject, so every check of the
     * scoped manager denies as `subject_unresolved`, whoever the current
     * request is about.
     *
     * @param  object|null  $user
     * @return self
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidPreviewException
     */
    public function forUser(?object $user): self
    {
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
     * now. The caller must be allowed `authorization:subject.preview` on the
     * preview resource naming the subject and the scope (see
     * `Preview\PreviewAdmission`), decided as an ordinary check about the
     * caller, with its own session, denies, boundaries, guardrails and caps:
     * now, and again at every use of the preview, each check, batch, listing
     * and execution of a query scoped through it, so a revocation is seen at
     * the next use. A refusal throws `AuthorizationException` before anything
     * about the subject is decided.
     *
     * `check()`, `can()`, `cannot()`, `any()`, `all()`, `authorize()`,
     * `explain()`, `checkMany()`, `canEach()`, `filterAuthorized()`,
     * `permissionsFor()` with a null subject, and `whereAuthorized()` given the
     * preview decide about the subject through the one decision path, each
     * decision reported with both parties and every listed action reported too
     * (see `PreviewContext`). Nothing a preview evaluates may change the
     * package's records, and its queries are read-only.
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
        $this->refuseOnPreview('previewFor');
        $this->refuseOverride();

        $context = PreviewContext::of($this->scopedTo($this->currentSubject()), $subject, $scope ?? AuthorizationScope::current());

        Previewing::current()->during($context->admit(...));

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
        $scoped           = clone $this;
        $scoped->pipeline = $this->pipeline->capped($actions);

        return $scoped;
    }

    /**
     * Return a clone of this manager deciding about the supplied subject, or
     * about no subject when it is null.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject|null  $subject
     * @return self
     */
    private function scopedTo(?Subject $subject): self
    {
        $scoped                  = clone $this;
        $scoped->subjectOverride = $subject;
        $scoped->isSubjectNamed  = true;

        return $scoped;
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
     * hypothetical policies would stand in for the stored ones.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidPreviewException
     */
    private function refuseOverride(): void
    {
        if ($this->pipeline->hasPolicyOverride()) {
            throw InvalidPreviewException::hypothetical();
        }
    }
}
