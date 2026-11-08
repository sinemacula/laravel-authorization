<?php

declare(strict_types = 1);

namespace Tests\Feature\Events;

use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionEffect;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Events\AuthorizationFailed;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use Tests\Concerns\DecidesOnAttributeValues;
use Tests\Concerns\ReadsDispatchedEvents;
use Tests\TestCase;

/**
 * Feature tests for `AuthorizationFailed` as the manager dispatches it when
 * `authorize()` refuses: the same references, names and ids as the decision's
 * `DecisionEvaluated`, never a model, the caller's context or a value the
 * decision read (AUTHZ-15.3, AUTHZ-15.4).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthorizationFailed::class)]
final class AuthorizationFailedTest extends TestCase
{
    use DecidesOnAttributeValues, ReadsDispatchedEvents;

    /**
     * A refusal by `authorize()` whose conditions read attribute values and a
     * value the caller passed reports what its `DecisionEvaluated` reports, and
     * none of the values.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException
     */
    public function testARefusalReportsWhatItsDecisionEventDoesButNoValue(): void
    {
        $user = $this->valueReadingSubject();
        $post = self::postWithStatus(self::SECRET_DRAFT);

        Event::fake([DecisionEvaluated::class, AuthorizationFailed::class]);

        try {
            Authorization::withPolicies([self::valueReadingPolicy()])->authorize(self::VALUE_ACTION, $post, ['reason' => self::SECRET_INPUT]);

            self::fail('The check is refused.');
        } catch (AuthorizationException $exception) {
            self::assertSame(DecisionReason::CONDITION_FAILED, $exception->getReason());
        }

        $evaluated = self::dispatchedEvents(DecisionEvaluated::class);
        $failed    = self::dispatchedEvents(AuthorizationFailed::class);

        self::assertCount(1, $failed);
        self::assertEquals(\get_object_vars($evaluated[0]), \get_object_vars($failed[0]));
        self::assertEquals(Reference::of($user), $failed[0]->subject);
        self::assertSame(DecisionEffect::DENY, $failed[0]->effect);
        self::assertSame(['resource.status', 'subject.department', 'input.reason'], $failed[0]->keys);
        self::assertCarriesNoValue($failed[0]);
    }

    /**
     * A refusal by `authorize()` on a resource of a tenant below the request's
     * names the resource's tenant, where it was decided, as its
     * `DecisionEvaluated` does.
     *
     * @return void
     */
    public function testARefusalNamesTheScopeItWasDecidedIn(): void
    {
        $this->valueReadingSubject();

        $child = $this->childTenant();

        Event::fake([DecisionEvaluated::class, AuthorizationFailed::class]);

        self::assertRefused(static fn () => Authorization::authorize(self::VALUE_ACTION, ResourceReference::record('posts', '7', Reference::of($child))));

        $evaluated = self::dispatchedEvents(DecisionEvaluated::class);
        $failed    = self::dispatchedEvents(AuthorizationFailed::class);

        self::assertCount(1, $failed);
        self::assertEquals(Reference::of($child), $failed[0]->tenant);
        self::assertSame('admin', $failed[0]->application);
        self::assertEquals(\get_object_vars($evaluated[0]), \get_object_vars($failed[0]));
    }

    /**
     * A refusal whose decision a listener replaced as the last decision, by
     * deciding another check, names the scope in place, the request's.
     *
     * @return void
     */
    public function testARefusalWhoseDecisionWasReplacedNamesTheScopeInPlace(): void
    {
        $this->valueReadingSubject();

        $child = $this->childTenant();

        /** @var \ArrayObject<int, \SineMacula\Laravel\Authorization\Events\AuthorizationFailed> $failed */
        $failed = new \ArrayObject;

        Event::listen(DecisionEvaluated::class, static function (DecisionEvaluated $event): void {
            if ($event->action !== self::VALUE_ACTION) {
                return;
            }

            Authorization::check('posts:audit');
        });
        Event::listen(AuthorizationFailed::class, static fn (AuthorizationFailed $event) => $failed->append($event));

        self::assertRefused(static fn () => Authorization::authorize(self::VALUE_ACTION, ResourceReference::record('posts', '7', Reference::of($child))));

        $reported = \array_values($failed->getArrayCopy());

        self::assertCount(1, $reported);
        self::assertSame(self::VALUE_ACTION, $reported[0]->action);
        self::assertSame('tenant-1', $reported[0]->tenant?->id);
        // The last decision is the listener's, made in the request's tenant,
        // not the refused one, made in the resource's.
        self::assertSame('tenant-1', Authorization::lastDecisionProvenance()?->tenant?->id);
    }

    /**
     * A decision the pipeline did not make, reported as a refusal, names the
     * current subject, the resource and the decision's reason.
     *
     * @return void
     */
    public function testAReportedRefusalNamesTheSubjectAndTheResource(): void
    {
        $user = $this->valueReadingSubject();

        Event::fake([AuthorizationFailed::class]);

        $decision = Decision::deny(DecisionReason::ADMINISTRATION_CONFLICT, DecisionStage::ADMINISTRATION);
        /** @var \SineMacula\Laravel\Authorization\AuthorizationManager $manager */
        $manager   = $this->app?->make(AuthorizationManager::class);
        $exception = $manager->reportRefusal('posts:edit', ['posts', 7], $decision);
        $failed    = self::dispatchedEvents(AuthorizationFailed::class);

        self::assertSame(DecisionReason::ADMINISTRATION_CONFLICT, $exception->getReason());
        self::assertCount(1, $failed);
        self::assertEquals(Reference::of($user), $failed[0]->subject);
        self::assertSame('posts:7', $failed[0]->resource);
        self::assertSame('posts:edit', $failed[0]->action);
        self::assertSame(DecisionReason::ADMINISTRATION_CONFLICT, $failed[0]->reason);
        self::assertSame('admin', $failed[0]->application);
    }

    /**
     * Assert the call is refused with an `AuthorizationException`.
     *
     * @param  \Closure(): mixed  $call
     * @return void
     */
    private static function assertRefused(\Closure $call): void
    {
        try {
            $call();

            self::fail('The check is refused.');
        } catch (AuthorizationException $exception) {
            self::assertSame(DecisionReason::NO_MATCH, $exception->getReason());
        }
    }
}
