<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Preview;

use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\DecisionProvenance;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidPreviewException;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\AuthorizationScope;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
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
 * each execution of a query scoped through it, first admits it again: the
 * previewer is decided `authorization:subject.preview` on the preview resource,
 * through the previewer's own manager, with its session, denies, boundaries,
 * guardrails and caps, recorded and reported as any check is (see
 * `PreviewAdmission`). Admission is never kept from one use to the next, so a
 * right revoked meanwhile refuses the next use. A refusal throws
 * `AuthorizationException`, carrying the previewer's decision, before anything
 * about the target is decided, so it reveals nothing about the target. Once
 * admitted, the target is evaluated in the scope, which is put in place for the
 * tenant and the application, and restored afterwards, even when the evaluation
 * throws (see `AuthorizationScope`). The whole use runs marked as a preview
 * being evaluated (see `Previewing`), so nothing it calls acts with authority.
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
        $reference = DecisionProvenance::of($previewer)->subject ?? throw self::refusal(Decision::deny(DecisionReason::SUBJECT_UNRESOLVED, DecisionStage::SUBJECT));

        // A copy of its own, with no session, so the previewer's subject is
        // never taken for the target, even when it previews itself.
        $named   = $target instanceof Subject ? $target : $previewer?->withSubject($target) ?? new Subject($target, $target);
        $subject = new Subject($named->subject, $named->identity, $named->tenant, $named->application, $named->guard);

        $about     = DecisionProvenance::of($subject);
        $previewed = $about->subject ?? throw InvalidPreviewException::unidentified();
        $resource  = new PreviewResource($previewed, $about->identity, $scope->tenant, $scope->application);

        return new self($reference, Previewing::current()->track($subject), $scope, $resource, $admitter);
    }

    /**
     * Admit the preview, then evaluate it through the callback, given the
     * target in the scope, with the scope in place, and return what the
     * callback returns, the whole marked as a preview being evaluated. A
     * refused admission throws `AuthorizationException` (see `admit()`) before
     * the callback is called.
     *
     * @template TResult
     *
     * @param  \Closure(\SineMacula\Laravel\Authorization\Subject|null): TResult  $evaluate
     * @return TResult
     */
    public function run(\Closure $evaluate): mixed
    {
        return Previewing::current()->during(function () use ($evaluate): mixed {
            $this->admit();

            return $this->scope->within(fn (): mixed => $evaluate($this->scope->subjectIn($this->target)));
        });
    }

    /**
     * Decide the previewer `authorization:subject.preview` on the preview
     * resource, through the previewer's manager, recorded and reported as
     * `authorize()` records and reports a refusal, and throw
     * `AuthorizationException`, carrying that decision, when it is not allowed,
     * a step-up the right needs included.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public function admit(): void
    {
        try {
            $this->admitter->authorize(PackagePermissions::SUBJECT_PREVIEW, $this->resource);
        } catch (InsufficientAuthenticationException $exception) {
            throw self::refusal($exception->getDecision() ?? Decision::deny(DecisionReason::INSUFFICIENT_AUTHENTICATION, DecisionStage::ALLOW));
        }
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
     * Return the refusal the decision makes, an `AuthorizationException` with
     * its reason and the one `denied` line, carrying the decision.
     *
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Decision  $decision
     * @return \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    private static function refusal(Decision $decision): AuthorizationException
    {
        return ActingContext::refusal($decision);
    }
}
