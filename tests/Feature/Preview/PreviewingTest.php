<?php

declare(strict_types = 1);

namespace Tests\Feature\Preview;

use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\Enums\GrantOutcome;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\LastDecisionStore;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Preview\Previewing;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Subject;
use Tests\Concerns\CatchesRefusals;
use Tests\Concerns\PreviewsSubjects;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for `Previewing`, what the request or job knows of its previews
 * (N87): nothing a preview evaluates, and nothing built from one, acts with
 * authority, and nothing of a request's previews reaches the next.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(Previewing::class)]
final class PreviewingTest extends TestCase
{
    use CatchesRefusals, PreviewsSubjects;

    /**
     * A listener that calls a management service while a preview decides, a
     * trusted call or a delegated one, is refused as
     * `administration.previewing`, and nothing is written; once the preview has
     * decided, the same call is made.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMutationWhileAPreviewIsEvaluatedIsRefused(): void
    {
        $caller  = self::previewer();
        $target  = self::target();
        $grantee = StubIdentity::query()->create(['id' => 'grantee']);
        $preview = $this->signIn($caller)->previewFor($target);
        $grant   = static fn (): GrantOutcome => self::grants()->grantPermission($grantee, self::permission('posts:edit'));
        /** @var \ArrayObject<int, mixed> $calls */
        $calls = new \ArrayObject;

        Event::listen(DecisionEvaluated::class, static function (DecisionEvaluated $event) use ($grant, $calls): void {
            if ($event->previewer === null) {
                return;
            }

            try {
                $grant();
            } catch (\Exception $exception) {
                $calls[] = $exception instanceof AuthorizationException ? [$exception->getReason(), $exception->getDecision()?->stage] : $exception;

                throw $exception;
            }
        });

        $refusal = self::refusalOf(static fn (): mixed => $preview->check('posts:read'));

        self::assertInstanceOf(AuthorizationException::class, $refusal);
        self::assertSame(DecisionReason::ADMINISTRATION_PREVIEWING, $refusal->getReason());

        self::assertSame([[DecisionReason::ADMINISTRATION_PREVIEWING, DecisionStage::ADMINISTRATION]], $calls->getArrayCopy());
        self::assertFalse($grantee->fresh()?->hasPermission('posts:edit'));
        self::assertSame(GrantOutcome::GRANTED, $grant());
    }

    /**
     * An acting context built while a preview is evaluated, or built from a
     * preview's target, is refused as `administration.previewing`; one the
     * application builds for the same model outside a preview is its own.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnActingContextBuiltWhileOrFromAPreviewIsRefused(): void
    {
        $caller  = self::previewer();
        $target  = self::target();
        $preview = $this->signIn($caller)->previewFor($target);
        $built   = [];

        Event::listen(DecisionEvaluated::class, static function (DecisionEvaluated $event) use (&$built): void {
            if ($event->previewer === null) {
                return;
            }

            foreach ([static fn (): ActingContext => ActingContext::current(), static fn (): ActingContext => ActingContext::for(new \stdClass)] as $build) {
                try {
                    $build();
                } catch (AuthorizationException $exception) {
                    $built[] = $exception->getReason();
                }
            }
        });

        $preview->check('posts:read');

        self::assertSame([DecisionReason::ADMINISTRATION_PREVIEWING, DecisionReason::ADMINISTRATION_PREVIEWING], $built);

        $subject = $preview->currentSubject();

        self::assertInstanceOf(Subject::class, $subject);

        try {
            ActingContext::for($subject);
            self::fail('An acting context was built from a preview.');
        } catch (AuthorizationException $exception) {
            self::assertSame(DecisionReason::ADMINISTRATION_PREVIEWING, $exception->getReason());
        }

        self::assertSame($target, ActingContext::for($target)->subject->subject);
        self::assertSame($caller, ActingContext::current()->subject->subject);
    }

    /**
     * A preview is evaluated from the start of the callback until it returns or
     * throws, nested ones included.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnEvaluationLastsUntilItsCallbackReturnsOrThrows(): void
    {
        $previews = new Previewing;
        $nested   = $previews->during(static fn (): array => [$previews->isEvaluating(), $previews->during($previews->isEvaluating(...))]);

        self::assertSame([true, true], $nested);

        try {
            $previews->during(self::failing(...));
        } catch (\RuntimeException) {
            // The evaluation must end with a callback that throws.
        }

        self::assertFalse($previews->isEvaluating());
    }

    /**
     * A target is remembered by its subject, the very instance, and held only
     * as long as something else holds it.
     *
     * @return void
     */
    public function testTargetsAreRememberedByInstanceAndHeldWeakly(): void
    {
        $previews = new Previewing;
        $model    = new \stdClass;
        $target   = new Subject($model, $model);

        self::assertSame($target, $previews->track($target));
        self::assertTrue($previews->isTarget($target));
        self::assertFalse($previews->isTarget(new Subject($model, $model)));

        $weak = \WeakReference::create($target);

        unset($target);

        self::assertNull($weak->get());
    }

    /**
     * The previews belong to the request or job: a new one starts with none
     * evaluated and no target known, and with no last decision.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRequestsAndJobsAreIsolatedFromEachOther(): void
    {
        $caller  = self::previewer();
        $target  = self::target();
        $preview = $this->signIn($caller)->previewFor($target);
        $first   = Previewing::current();
        $subject = $preview->currentSubject();

        $app = $this->app;

        self::assertNotNull($app);
        self::assertInstanceOf(Subject::class, $subject);
        self::assertTrue($first->isTarget($subject));
        self::assertNotNull($app->make(LastDecisionStore::class)->get());

        $app->forgetScopedInstances();

        $next = Previewing::current();

        self::assertNotSame($first, $next);
        self::assertFalse($next->isTarget($subject));
        self::assertFalse($next->isEvaluating());
        self::assertNull($app->make(LastDecisionStore::class)->get());
    }

    /**
     * Without the binding, nothing is refused, and the previews are bound,
     * scoped, on first use; the refusal is `administration.previewing` at the
     * administration stage, with the one `denied` line.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheBindingIsMadeOnFirstUseAndTheRefusalIsGeneric(): void
    {
        $app = $this->app;

        self::assertNotNull($app);

        $app->offsetUnset(Previewing::class);

        Previewing::refuseAuthority();

        self::assertFalse($app->bound(Previewing::class));

        $first = Previewing::current();

        self::assertSame($first, Previewing::current());

        $app->forgetScopedInstances();

        self::assertNotSame($first, Previewing::current());

        $refusal = Previewing::refusal();

        self::assertSame(DecisionReason::ADMINISTRATION_PREVIEWING, $refusal->getReason());
        self::assertSame(DecisionStage::ADMINISTRATION, $refusal->getDecision()?->stage);
        self::assertSame('This action is unauthorized.', $refusal->getMessage());
    }

    /**
     * Fail, as an evaluation that throws does.
     *
     * @return never
     *
     * @throws \RuntimeException
     */
    private static function failing(): never
    {
        throw new \RuntimeException('Failed.');
    }

    /**
     * Return the grant service.
     *
     * @return \SineMacula\Laravel\Authorization\Services\GrantService
     */
    private static function grants(): GrantService
    {
        $service = GrantService::instance();

        self::assertInstanceOf(GrantService::class, $service);

        return $service;
    }
}
