<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Preview;

use Illuminate\Container\Container;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Subject;

/**
 * What the current request or job knows of its previews (AUTHZ-11.4, N84 to
 * N87): whether a preview is being evaluated, which subjects are the targets of
 * its previews, so nothing a preview evaluates, and nothing built from one,
 * acts with authority, and which subject each use of a preview decides about,
 * so each of its decisions is admitted where it is made.
 *
 * While a preview is evaluated (`during()`), from its admission to its last
 * decision and the report of its refusal, a callback or a listener it runs that
 * calls a package mutation service is refused as `administration.previewing`
 * (see `OperationScope`), and so is an acting context built then (see
 * `ActingContext`); an acting context built from a preview's target, the
 * subject a preview manager's `currentSubject()` returns, is refused the same
 * way, whenever it is built. There is no override: a preview never confers
 * authority to change anything.
 *
 * While a use of a preview runs (`evaluating()`), the subject it decides about
 * is held with the use's admission (see `PreviewAdmission`), so wherever the
 * decision pipeline gathers that subject's sources, the scope a check, a
 * further check or a query's class of rows is decided in, the preview is
 * admitted there first (`admit()`), and the query scope reads the previewer's
 * anchors beside the target's (`previewerOf()`). Any other subject, the
 * previewer's own in its admission or in a listener included, is decided as it
 * always is.
 *
 * It is bound with `scoped()`, so it belongs to the current request or job,
 * like the last decision, and holds nothing across them; its targets and its
 * uses are held weakly, so a preview that is let go is forgotten. It is never
 * kept in a static property.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class Previewing
{
    /** @var int How many previews are being evaluated, one inside another's callback included. */
    private int $depth = 0;

    /** @var \WeakMap<\SineMacula\Laravel\Authorization\Subject, bool> The targets of the previews built in the request or job, each true. */
    private \WeakMap $targets;

    /** @var \WeakMap<\SineMacula\Laravel\Authorization\Subject, \SineMacula\Laravel\Authorization\Preview\PreviewAdmission> Each running use's subject, with its admission. */
    private \WeakMap $uses;

    /**
     * Create the previews of a request or job, none evaluated and none built.
     */
    public function __construct()
    {
        $this->targets = new \WeakMap;
        $this->uses    = new \WeakMap;
    }

    /**
     * Return the previews of the current request or job, binding them, scoped,
     * when the container does not yet hold them.
     *
     * @return self
     */
    public static function current(): self
    {
        $container = Container::getInstance();

        if (!$container->bound(self::class)) {
            $container->scoped(self::class);
        }

        /** @var self */
        return $container->make(self::class);
    }

    /**
     * Refuse when a preview is being evaluated, or when the subject is the
     * target of a preview, with `administration.previewing`.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject|null  $subject
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public static function refuseAuthority(?Subject $subject = null): void
    {
        $container = Container::getInstance();

        if (!$container->bound(self::class)) {
            return;
        }

        $previews = self::current();

        if ($previews->isEvaluating() || ($subject !== null && $previews->isTarget($subject))) {
            throw self::refusal();
        }
    }

    /**
     * Admit the use of a preview deciding about the subject, when one is
     * running, in the scope in place (see `PreviewAdmission::admitHere()`):
     * what the decision pipeline calls before it gathers the subject's sources.
     * A refused admission throws `AuthorizationException`. Nothing is done for
     * any other subject.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return void
     */
    public static function admit(Subject $subject): void
    {
        $admission = Container::getInstance()->bound(self::class) ? self::current()->uses[$subject] ?? null : null;

        if ($admission === null) {
            return;
        }

        // Called through a closure, as a preview's use is (see
        // `PreviewContext::run()`), so the refusal it throws is not declared on
        // every path of the decision pipeline.
        self::call($admission->admitHere(...));
    }

    /**
     * Return the previewer of the use of a preview deciding about the subject,
     * when one is running, or null for any other subject.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return \SineMacula\Laravel\Authorization\Subject|null
     */
    public static function previewerOf(Subject $subject): ?Subject
    {
        return Container::getInstance()->bound(self::class) ? (self::current()->uses[$subject] ?? null)?->previewer() : null;
    }

    /**
     * Run the callback as a use of a preview deciding about the subject, with
     * the use's admission, and return what it returns, marked as evaluating,
     * and the subject held with the admission, until it returns or throws.
     *
     * @template TResult
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @param  \SineMacula\Laravel\Authorization\Preview\PreviewAdmission  $admission
     * @param  \Closure(): TResult  $callback
     * @return TResult
     */
    public function evaluating(Subject $subject, PreviewAdmission $admission, \Closure $callback): mixed
    {
        $this->uses[$subject] = $admission;

        try {
            return $this->during($callback);
        } finally {
            unset($this->uses[$subject]);
        }
    }

    /**
     * Run the callback as the evaluation of a preview, and return what it
     * returns, marked as evaluating until it returns or throws.
     *
     * @template TResult
     *
     * @param  \Closure(): TResult  $callback
     * @return TResult
     */
    public function during(\Closure $callback): mixed
    {
        $this->depth++;

        try {
            return $callback();
        } finally {
            $this->depth--;
        }
    }

    /**
     * Determine whether a preview is being evaluated.
     *
     * @return bool
     */
    public function isEvaluating(): bool
    {
        return $this->depth > 0;
    }

    /**
     * Remember the subject as the target of a preview, and return it.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $target
     * @return \SineMacula\Laravel\Authorization\Subject
     */
    public function track(Subject $target): Subject
    {
        $this->targets[$target] = true;

        return $target;
    }

    /**
     * Determine whether the subject is the target of a preview built in the
     * request or job.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return bool
     */
    public function isTarget(Subject $subject): bool
    {
        return $this->targets[$subject] ?? false;
    }

    /**
     * Return the refusal of anything that would act with authority from a
     * preview: an `AuthorizationException` as `administration.previewing`,
     * carrying the denial, with the one `denied` line, as an acting context's
     * refusal is worded (see `ActingContext::refusal()`).
     *
     * @return \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public static function refusal(): AuthorizationException
    {
        return ActingContext::refusal(Decision::deny(DecisionReason::ADMINISTRATION_PREVIEWING, DecisionStage::ADMINISTRATION));
    }

    /**
     * Call the callback.
     *
     * @param  \Closure(): void  $callback
     * @return void
     */
    private static function call(\Closure $callback): void
    {
        $callback();
    }
}
