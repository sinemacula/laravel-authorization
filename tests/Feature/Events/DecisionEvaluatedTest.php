<?php

declare(strict_types = 1);

namespace Tests\Feature\Events;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionEffect;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\DecidesOnAttributeValues;
use Tests\Concerns\ReadsDispatchedEvents;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubTenant;
use Tests\TestCase;

/**
 * Feature tests for `DecisionEvaluated` as the manager dispatches it: the
 * subject and its identity, the tenant and application, the action, the
 * resource, the effect and reason, the deciding statements and the keys the
 * decision depended on, as references, names and ids, never a model, the
 * caller's context or a value the decision read (AUTHZ-15.3, AUTHZ-15.4).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DecisionEvaluated::class)]
final class DecisionEvaluatedTest extends TestCase
{
    use DecidesOnAttributeValues, ReadsDispatchedEvents;

    /** @var list<string> Every property a decision event has, in order. */
    private const array PROPERTIES = [
        'subject', 'identity', 'previewer', 'action', 'resource', 'tenant', 'application', 'effect', 'reason', 'statements', 'usedBreakGlass', 'keys',
    ];

    /**
     * An allow whose conditions read a resource attribute, a subject attribute
     * and a value the caller passed carries references to the subject, its
     * identity and its tenant, the application, the action, the resource, the
     * deciding statement and the keys it read, and none of the values.
     *
     * @return void
     */
    public function testAnAllowCarriesReferencesAndKeysButNoValue(): void
    {
        $user = $this->valueReadingSubject();
        $post = self::postWithStatus(self::SECRET_STATUS);

        Event::fake([DecisionEvaluated::class]);

        $decision = Authorization::withPolicies([self::valueReadingPolicy()])->check(self::VALUE_ACTION, $post, ['reason' => self::SECRET_INPUT]);
        $events   = self::dispatchedEvents(DecisionEvaluated::class);

        self::assertTrue($decision->isAllowed());
        self::assertCount(1, $events);

        $event = $events[0];

        self::assertSame(self::PROPERTIES, \array_keys(\get_object_vars($event)));
        self::assertEquals(Reference::of($user), $event->subject);
        self::assertEquals(Reference::of($user), $event->identity);
        self::assertNull($event->previewer);
        self::assertSame(self::VALUE_ACTION, $event->action);
        self::assertSame($post->getMorphClass() . ':' . self::keyOf($post), $event->resource);
        self::assertEquals(new Reference((new StubTenant)->getMorphClass(), 'tenant-1'), $event->tenant);
        self::assertSame('admin', $event->application);
        self::assertSame(DecisionEffect::ALLOW, $event->effect);
        self::assertNull($event->reason);
        self::assertSame($decision->statements, $event->statements);
        self::assertSame('read-audited', $event->statements[0]->sid);
        self::assertFalse($event->usedBreakGlass);
        self::assertSame(['resource.status', 'subject.department', 'input.reason'], $event->keys);
        self::assertCarriesNoValue($event);
    }

    /**
     * A denial because a condition failed carries the keys it read, held or
     * failed, its reason, and still none of the values.
     *
     * @return void
     */
    public function testADenialCarriesItsKeysButNoValue(): void
    {
        $this->valueReadingSubject();

        $post = self::postWithStatus(self::SECRET_DRAFT);

        Event::fake([DecisionEvaluated::class]);

        $decision = Authorization::withPolicies([self::valueReadingPolicy()])->check(self::VALUE_ACTION, $post, ['reason' => self::SECRET_INPUT]);
        $events   = self::dispatchedEvents(DecisionEvaluated::class);

        self::assertFalse($decision->isAllowed());
        self::assertCount(1, $events);
        self::assertFalse($events[0]->isAllowed());
        self::assertSame(DecisionEffect::DENY, $events[0]->effect);
        self::assertSame($decision->reason, $events[0]->reason);
        self::assertSame(['resource.status', 'subject.department', 'input.reason'], $events[0]->keys);
        self::assertCarriesNoValue($events[0]);
    }

    /**
     * A decision about a guest names no subject, identity, tenant or
     * application, never filling them from the request's subject.
     *
     * @return void
     */
    public function testAGuestsDecisionNamesNoSubject(): void
    {
        $this->valueReadingSubject();

        Event::fake([DecisionEvaluated::class]);

        Authorization::forUser(null)->check(self::VALUE_ACTION);

        $events = self::dispatchedEvents(DecisionEvaluated::class);

        self::assertCount(1, $events);
        self::assertNull($events[0]->subject);
        self::assertNull($events[0]->identity);
        self::assertNull($events[0]->tenant);
        self::assertNull($events[0]->application);
        self::assertSame(DecisionReason::SUBJECT_UNRESOLVED, $events[0]->reason);
    }

    /**
     * A decision about a subject named with `for()` names that subject, as its
     * own identity, in the request's tenant and application, never the
     * request's subject.
     *
     * @return void
     */
    public function testANamedSubjectsDecisionNamesThatSubject(): void
    {
        $this->valueReadingSubject();

        $other = StubIdentity::create(['id' => 'user-2']);

        Event::fake([DecisionEvaluated::class]);

        Authorization::for($other)->check(self::VALUE_ACTION);

        $events = self::dispatchedEvents(DecisionEvaluated::class);

        self::assertCount(1, $events);
        self::assertEquals(Reference::of($other), $events[0]->subject);
        self::assertEquals(Reference::of($other), $events[0]->identity);
        self::assertSame('tenant-1', $events[0]->tenant?->id);
        self::assertSame('admin', $events[0]->application);
    }

    /**
     * Return the model's key, as text.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return string
     */
    private static function keyOf(Model $model): string
    {
        $key = $model->getKey();

        return \is_int($key) || \is_string($key) ? (string) $key : '';
    }
}
