<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Concerns;

use SineMacula\Laravel\Authorization\Subject;

/**
 * The scoped clones of the authorization manager: `for()` and `forUser()`,
 * which name the subject its checks are about, and `withPolicies()` and
 * `capped()`, which change how they are decided. Each returns a clone, so the
 * manager it is called on is unchanged.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait BuildsScopedManagers
{
    /**
     * Return a scoped manager deciding about the supplied subject.
     *
     * The decisions keep the current request's tenant, application and guard,
     * as the resolver reports them; with no subject resolved, they have none.
     *
     * @param  object  $subject
     * @return self
     */
    public function for(object $subject): self
    {
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
     */
    public function forUser(?object $user): self
    {
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
     */
    public function withPolicies(array $policies): self
    {
        $scoped           = clone $this;
        $scoped->pipeline = $this->pipeline->withPolicies($policies);

        return $scoped;
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
     * scopes, which is allowed nothing, a cap never stands in for them.
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
}
