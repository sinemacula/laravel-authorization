<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Preview;

use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\DecisionProvenance;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidPreviewException;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\AuthorizationScope;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Who is previewing whom, and where (AUTHZ-11.4, N84 to N87): what a preview
 * manager from `Authorization::previewFor()` carries, fixed when it is built.
 *
 * The previewer is the real caller, the subject the manager `previewFor()` was
 * called on decides about, its session kept, never inferred later from the
 * target, the authenticated user or a listener. The target is the subject
 * previewed, with no session: a resolved `Subject` keeps its principal and its
 * identity but loses its session, and a model is named as `for()` names it, so
 * no authentication requirement made of the target is ever met, whatever the
 * previewer has proved. The scope is the tenant and application the target is
 * evaluated in, given, or the request's when the preview was built.
 *
 * Every use of the preview (`run()`), each check, each batch, each listing and
 * each compile of a query scoped through it, is admitted afresh (see
 * `PreviewAdmission`): first in the preview's scope, then wherever one of its
 * decisions about the target is made, a resource's own tenant, the tenants
 * below it or the platform, each scope once in the use. The previewer is
 * decided `authorization:subject.preview` there on the preview resource,
 * through the previewer's own manager, with its session, denies, boundaries,
 * guardrails and caps, recorded and reported as any check is. Admission is
 * never kept from one use to the next, so a right revoked meanwhile refuses the
 * next use. A refusal throws `AuthorizationException`, carrying the previewer's
 * decision, before anything about the target is decided in that scope, so it
 * reveals nothing about the target there; in a batch, a listing or a query, it
 * refuses the whole call, which returns nothing. Once admitted, the target is
 * evaluated in the scope, which is put in place for the tenant and the
 * application, and restored afterwards, even when the evaluation throws (see
 * `AuthorizationScope`). The whole use runs marked as a preview being evaluated
 * (see `Previewing`), so nothing it calls acts with authority, and with the
 * request's resolution memo set aside and restored afterwards (see
 * `ResolutionCache::batch()`), so a use leaves what the caller's own checks
 * have resolved in place.
 *
 * The target is evaluated in the caller's request context: what the request,
 * the environment and the authentication namespace supply is the caller's
 * request's, read as it is now, which is no prediction of what the target would
 * see when signed in.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PreviewContext
{
    /**
     * Create a new preview context.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference  $previewer
     * @param  \SineMacula\Laravel\Authorization\Subject  $target
     * @param  \SineMacula\Laravel\Authorization\Support\AuthorizationScope  $scope
     * @param  \SineMacula\Laravel\Authorization\Preview\PreviewResource  $resource
     * @param  \SineMacula\Laravel\Authorization\AuthorizationManager  $admitter
     */
    private function __construct(

        /** The previewer, the real caller, by reference to its principal. */
        public Reference $previewer,

        /** The subject previewed, with no session. */
        public Subject $target,

        /** The tenant and application the target is evaluated in. */
        public AuthorizationScope $scope,

        /** The resource the preview's admission is decided on. */
        private PreviewResource $resource,

        /** The previewer's own manager, which decides the preview's admission. */
        private AuthorizationManager $admitter,
    ) {}

    /**
     * Return the preview of the target, a resolved `Subject` or a model, by the
     * previewer, admitted through the previewer's manager, in the scope. The
     * target loses any session; a model is named in the previewer's request, as
     * `for()` names it. A previewer that names no record, a guest included, is
     * refused as `subject_unresolved` before anything is decided, and a target
     * that names no record is refused with `InvalidPreviewException`, since no
     * preview event could name either.
     *
     * @param  \SineMacula\Laravel\Authorization\AuthorizationManager  $admitter
     * @param  object  $target
     * @param  \SineMacula\Laravel\Authorization\Support\AuthorizationScope  $scope
     * @return self
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidPreviewException
     */
    public static function of(AuthorizationManager $admitter, object $target, AuthorizationScope $scope): self
    {
        $previewer = $admitter->currentSubject();
        $reference = DecisionProvenance::of($previewer)->subject ?? throw self::unresolved();

        /** @var \SineMacula\Laravel\Authorization\Subject $previewer */

        // A copy of its own, with no session, so the previewer's subject is
        // never taken for the target, even when it previews itself.
        $named   = $target instanceof Subject ? $target : $previewer->withSubject($target);
        $subject = new Subject($named->subject, $named->identity, $named->tenant, $named->application, $named->guard);

        $about     = DecisionProvenance::of($subject);
        $previewed = $about->subject ?? throw InvalidPreviewException::unidentified();
        $resource  = new PreviewResource($previewed, $about->identity, $scope->tenant, $scope->application);

        return new self($reference, Previewing::current()->track($subject), $scope, $resource, $admitter);
    }

    /**
     * Admit the preview in its scope, then evaluate it through the callback,
     * given the target in the scope, with the scope in place, and return what
     * the callback returns: one use, every decision of which about the target
     * is admitted where it is made (see `PreviewAdmission`), the whole marked
     * as a preview being evaluated, with the request's resolution memo set
     * aside. A refused admission throws `AuthorizationException` before
     * anything about the target is decided where it is refused.
     *
     * @template TResult
     *
     * @param  \Closure(\SineMacula\Laravel\Authorization\Subject): TResult  $evaluate
     * @return TResult
     */
    public function run(\Closure $evaluate): mixed
    {
        $about     = $this->scope->subjectIn($this->target);
        $admission = new PreviewAdmission($this->admitter, $this->resource);
        $evaluated = static function () use ($admission, $evaluate, $about): mixed {
            $admission->admitHere();

            return $evaluate($about);
        };

        $use = fn (): mixed => Previewing::current()->evaluating($about, $admission, fn (): mixed => $this->scope->within($evaluated));

        $cache = ResolutionCache::instance();

        return $cache === null ? $use() : $cache->batch($use, true);
    }

    /**
     * Return the provenance of a decision about the target made in the
     * preview's scope, naming the previewer: what reports a decision whose own
     * provenance is no longer recorded.
     *
     * @return \SineMacula\Laravel\Authorization\Evaluation\DecisionProvenance
     */
    public function provenance(): DecisionProvenance
    {
        return $this->scope->within(fn (): DecisionProvenance => DecisionProvenance::of($this->target, $this->previewer));
    }

    /**
     * Refuse a scope whose tenant or application is not the preview's, which
     * would need an admission of its own.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\AuthorizationScope  $scope
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidPreviewException
     */
    public function refuseOtherScope(AuthorizationScope $scope): void
    {
        $own   = $this->scope->tenant;
        $asked = $scope->tenant;

        if ($own?->type !== $asked?->type || $own?->id !== $asked?->id || $this->scope->application !== $scope->application) {
            throw InvalidPreviewException::rescoped();
        }
    }

    /**
     * Return the refusal of a previewer that names no record, a guest included,
     * as `subject_unresolved`, an `AuthorizationException` with the one
     * `denied` line, carrying the denial.
     *
     * @return \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    private static function unresolved(): AuthorizationException
    {
        return ActingContext::refusal(Decision::deny(DecisionReason::SUBJECT_UNRESOLVED, DecisionStage::SUBJECT));
    }
}
