<?php

declare(strict_types = 1);

namespace Tests\Feature\Events;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Evaluation\DecisionProvenance;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionEffect;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Services\ApplicationAccess;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResolvedTenant;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use Tests\Concerns\DecidesOnAttributeValues;
use Tests\Concerns\ReadsDispatchedEvents;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubSubjectResolver;
use Tests\Feature\Stubs\StubTenant;
use Tests\TestCase;

/**
 * Feature tests for `DecisionEvaluated` as the manager dispatches it: the
 * subject and its identity, the tenant and application the decision was made
 * in, the action, the resource, the effect and reason, the deciding statements
 * and the keys the decision depended on, as references, names and ids, never a
 * model, the caller's context or a value the decision read (AUTHZ-15.3,
 * AUTHZ-15.4).
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
     * A decision about a guest names no subject or identity, never filling them
     * from the request's subject, and names the scope it was made in: the
     * request's, or the one put in place around it.
     *
     * @return void
     */
    public function testAGuestsDecisionNamesNoSubjectButTheScope(): void
    {
        $this->valueReadingSubject();

        $other = StubTenant::query()->create(['id' => 'tenant-2', 'name' => 'tenant-2']);

        Event::fake([DecisionEvaluated::class]);

        Authorization::forUser(null)->check(self::VALUE_ACTION);
        TenantScope::within($other, 'app', static fn (): bool => Authorization::forUser(null)->can(self::VALUE_ACTION));

        $events = self::dispatchedEvents(DecisionEvaluated::class);

        self::assertCount(2, $events);
        self::assertNull($events[0]->subject);
        self::assertNull($events[0]->identity);
        self::assertSame(DecisionReason::SUBJECT_UNRESOLVED, $events[0]->reason);
        self::assertEquals(new Reference($other->getMorphClass(), 'tenant-1'), $events[0]->tenant);
        self::assertSame('admin', $events[0]->application);
        self::assertNull($events[1]->subject);
        self::assertEquals(Reference::of($other), $events[1]->tenant);
        self::assertSame('app', $events[1]->application);
        self::assertEquals(new DecisionProvenance(null, null, null, Reference::of($other), 'app'), Authorization::lastDecisionProvenance());
    }

    /**
     * A check on a resource of a tenant below the request's is decided, and
     * reported, in the resource's own tenant, in the request's application.
     *
     * @return void
     */
    public function testACheckOnAResourceBelowTheRequestsTenantNamesItsTenant(): void
    {
        $user  = $this->valueReadingSubject();
        $child = $this->childTenant();

        Event::fake([DecisionEvaluated::class]);

        Authorization::check(self::VALUE_ACTION, ResourceReference::record('posts', '7', Reference::of($child)));

        $events = self::dispatchedEvents(DecisionEvaluated::class);

        self::assertCount(1, $events);
        self::assertEquals(Reference::of($user), $events[0]->subject);
        self::assertEquals(Reference::of($child), $events[0]->tenant);
        self::assertSame('admin', $events[0]->application);
        self::assertEquals(new DecisionProvenance(Reference::of($user), Reference::of($user), null, Reference::of($child), 'admin'), Authorization::lastDecisionProvenance());
    }

    /**
     * A resource of a tenant outside the request's, admitted by a platform-wide
     * grant, is decided, and reported, at platform scope, in the request's
     * application; one refused as out of scope is reported in the request's
     * scope, where it was refused.
     *
     * @return void
     */
    public function testAnOutsideResourceIsReportedWhereItWasDecided(): void
    {
        $this->valueReadingSubject();

        $outside  = StubTenant::query()->create(['id' => 'tenant-3', 'name' => 'tenant-3']);
        $resource = ResourceReference::record('posts', '7', Reference::of($outside));

        Event::fake([DecisionEvaluated::class]);

        $refused = Authorization::check(self::VALUE_ACTION, $resource);

        StubIdentity::query()->findOrFail('user-1')->givePermission(Permission::create(['name' => self::VALUE_ACTION]));

        $admitted = Authorization::check(self::VALUE_ACTION, $resource);
        $events   = self::dispatchedEvents(DecisionEvaluated::class);

        self::assertSame(DecisionReason::TENANT_SCOPE, $refused->reason);
        self::assertTrue($admitted->isAllowed());
        self::assertCount(2, $events);
        self::assertSame('tenant-1', $events[0]->tenant?->id);
        self::assertSame('admin', $events[0]->application);
        self::assertNull($events[1]->tenant);
        self::assertSame('admin', $events[1]->application);
        self::assertNull(Authorization::lastDecisionProvenance()?->tenant);
    }

    /**
     * Whether a principal may use an application is decided, and reported, in
     * the tenant and the application asked about, not the subject's.
     *
     * @return void
     */
    public function testAnApplicationAccessCheckNamesTheScopeItIsDecidedIn(): void
    {
        config(['authorization.application_access' => ['admin' => 'admin:access']]);

        $user = StubIdentity::create(['id' => 'user-1']);
        $own  = StubTenant::query()->create(['id' => 'tenant-a', 'name' => 'tenant-a']);

        Permission::create(['name' => 'admin:access']);

        $user->givePermission('admin:access', tenant: $own, application: 'admin');

        $this->app?->instance(SubjectResolver::class, new StubSubjectResolver($user, null, 'web'));
        $this->app?->forgetInstance(ResolvedTenant::class);

        Event::fake([DecisionEvaluated::class]);

        self::assertTrue($this->app?->make(ApplicationAccess::class)->mayUse('admin', $user, $own));

        $events = self::dispatchedEvents(DecisionEvaluated::class);

        self::assertCount(1, $events);
        self::assertEquals(Reference::of($own), $events[0]->tenant);
        self::assertSame('admin', $events[0]->application);
        self::assertEquals(Reference::of($own), Authorization::lastDecisionProvenance()?->tenant);
        self::assertSame('admin', Authorization::lastDecisionProvenance()?->application);
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
