<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Preview;

use Illuminate\Container\Container;
use Illuminate\Contracts\Translation\Translator;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Subject;

/**
 * What the current request or job knows of its previews (AUTHZ-11.4, N87):
 * whether a preview is being evaluated, and which subjects are the targets of
 * its previews, so nothing a preview evaluates, and nothing built from one,
 * acts with authority.
 *
 * While a preview is evaluated (`during()`), from its admission to its last
 * decision, a callback or a listener it runs that calls a package mutation
 * service is refused as `administration.previewing` (see `OperationScope`), and
 * so is an acting context built then (see `ActingContext`); an acting context
 * built from a preview's target, the subject a preview manager's
 * `currentSubject()` returns, is refused the same way, whenever it is built.
 * There is no override: a preview never confers authority to change anything.
 *
 * It is bound with `scoped()`, so it belongs to the current request or job,
 * like the last decision, and holds nothing across them; its targets are held
 * weakly, so a preview that is let go is forgotten. It is never kept in a
 * static property.
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

    /** @var \WeakMap<\SineMacula\Laravel\Authorization\Subject, true> The targets of the previews built in the request or job. */
    private \WeakMap $targets;

    /**
     * Create the previews of a request or job, none evaluated and none built.
     */
    public function __construct()
    {
        $this->targets = new \WeakMap;
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
        return isset($this->targets[$subject]);
    }

    /**
     * Return the refusal of anything that would act with authority from a
     * preview: an `AuthorizationException` as `administration.previewing`,
     * carrying the denial, with the one `denied` line the bound translator
     * words.
     *
     * @return \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public static function refusal(): AuthorizationException
    {
        $container  = Container::getInstance();
        $translator = $container->bound('translator') ? $container->make('translator') : null;
        $decision   = Decision::deny(DecisionReason::ADMINISTRATION_PREVIEWING, DecisionStage::ADMINISTRATION);

        return AuthorizationException::translated(DecisionReason::ADMINISTRATION_PREVIEWING, $translator instanceof Translator ? $translator : null, $decision);
    }
}
