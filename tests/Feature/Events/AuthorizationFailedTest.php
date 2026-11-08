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
}
