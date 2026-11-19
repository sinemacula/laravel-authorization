<?php

declare(strict_types = 1);

namespace Tests\Feature\Services;

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Events\Grantee\BreakGlassRevoked;
use SineMacula\Laravel\Authorization\Events\Grantee\BreakGlassSurrendered;
use SineMacula\Laravel\Authorization\Models\BreakGlassActivation;
use SineMacula\Laravel\Authorization\Services\Support\ActivationEnds;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\OperationScope;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\ActivatesBreakGlass;
use Tests\Concerns\ReadsDispatchedEvents;
use Tests\Concerns\RecordsRowLocks;
use Tests\Feature\Stubs\StubGrantee;
use Tests\Feature\Stubs\StubSecondGrantee;
use Tests\TestCase;

/**
 * Feature tests for ending break-glass activations.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ActivationEnds::class)]
final class ActivationEndsTest extends TestCase
{
    use ActivatesBreakGlass, ReadsDispatchedEvents, RecordsRowLocks;

    /** @var string How an instant is compared, to the microsecond. */
    private const string INSTANT = 'Y-m-d H:i:s.u';

    /** @var string When each end is recorded: the clock's instant, to the second. */
    private const string ENDED_AT = '2026-07-01 12:00:00.000000';

    /**
     * Start the clock.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow('2026-07-01 12:00:00.500000');
    }

    /**
     * Reset the clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * The grantee's activations not ended or expired are listed in key order
     * and locked, while break-glass is off too; an expired or ended one, and
     * one of another grantee or another type with the same key, are not.
     *
     * @return void
     */
    public function testListsTheGranteesUnexpiredActivationsLocked(): void
    {
        $user = StubGrantee::query()->create(['id' => 'user-1']);
        $role = self::emergencyRole();
        $live = [self::activate($user, $role)->id, self::activate($user, $role, ['expires_at' => Carbon::now()->addSecond()])->id];

        self::activate($user, $role, ['expires_at' => Carbon::now()]);
        self::activate($user, $role, ['ended_at' => Carbon::now()->subMinute()]);
        self::activate(StubGrantee::query()->create(['id' => 'user-2']), $role);
        self::activate(StubSecondGrantee::query()->create(['id' => 'user-1']), $role);
        self::switchBreakGlass(false);

        \sort($live);

        $locks  = $this->recordRowLocks();
        $listed = \array_map(static fn (BreakGlassActivation $activation): string => $activation->id, ActivationEnds::unexpiredOf(Reference::of($user)));

        self::assertSame($live, $listed);
        self::assertSame(['break_glass_activations'], \array_values(\array_unique(\array_column($locks->getArrayCopy(), 0))));
    }

    /**
     * An activation's revocation is decided under the revoke right, as only
     * narrowing, in the activation's tenant, for its grantee, role and scope.
     *
     * @return void
     */
    public function testARevocationIsDecidedInTheActivationsScope(): void
    {
        $user       = StubGrantee::query()->create(['id' => 'user-1']);
        $role       = self::emergencyRole();
        $tenant     = new Reference('tenant', 'acct1');
        $activation = self::activate($user, $role, ['tenant_type' => 'tenant', 'tenant_id' => 'acct1', 'include_subtree' => false, 'application' => 'admin']);
        $resource   = ActivationEnds::revocation($activation);

        self::assertSame([PackagePermissions::BREAK_GLASS_REVOKE, true], [$resource->action, $resource->isNarrowing]);
        self::assertEquals($tenant, $resource->tenant);
        self::assertEquals(Reference::of($user), $resource->change?->grantee);
        self::assertTrue($role->is($resource->change?->target));
        self::assertEquals(new GrantScope($tenant, 'admin', false), $resource->change?->scope);
    }

    /**
     * Ending an activation records when, to the second, by the operation's
     * actor and why, and reports it once as revoked or surrendered with its
     * role and scope; one ended or expired already changes nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEndsAnActivationOnceAndReportsIt(): void
    {
        $user    = StubGrantee::query()->create(['id' => 'user-1']);
        $role    = self::emergencyRole();
        $actor   = new Reference('stub_grantee', 'admin-1');
        $revoked = self::activate($user, $role, ['tenant_type' => 'tenant', 'tenant_id' => 'acct1'])->refresh();
        $given   = self::activate($user, $role)->refresh();
        $expired = self::activate($user, $role, ['expires_at' => Carbon::now()->startOfSecond()])->refresh();

        Event::fake([BreakGlassRevoked::class, BreakGlassSurrendered::class]);

        $ended = OperationScope::run(Operation::begin($actor), static fn (Operation $operation): array => [
            ActivationEnds::end($revoked, 'revoked', $operation),
            ActivationEnds::end($given, 'surrendered', $operation),
            ActivationEnds::end($revoked, 'revoked', $operation),
            ActivationEnds::end($expired, 'revoked', $operation),
        ]);

        $stored      = BreakGlassActivation::query()->findOrFail($revoked->id);
        $revocations = self::dispatchedEvents(BreakGlassRevoked::class);
        $event       = $revocations[0];

        self::assertSame([1, 1, 0, 0], $ended);
        self::assertSame(
            [self::ENDED_AT, 'stub_grantee', 'admin-1', 'revoked'],
            [$stored->ended_at?->format(self::INSTANT), $stored->ended_by_type, $stored->ended_by_id, $stored->end_reason],
        );
        self::assertSame('surrendered', BreakGlassActivation::query()->findOrFail($given->id)->end_reason);
        self::assertNull(BreakGlassActivation::query()->findOrFail($expired->id)->ended_at);
        self::assertCount(1, $revocations);
        self::assertEquals(
            [Reference::of($user), Reference::of($role), 'responder', new GrantScope(new Reference('tenant', 'acct1')), $revoked->id, self::ENDED_AT],
            [$event->grantee, $event->role, $event->name, $event->scope, $event->activation, $event->endedAt->format(self::INSTANT)],
        );
        self::assertSame([$given->id], \array_map(static fn (BreakGlassSurrendered $event): string => $event->activation, self::dispatchedEvents(BreakGlassSurrendered::class)));
    }
}
