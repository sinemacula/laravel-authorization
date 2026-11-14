<?php

declare(strict_types = 1);

namespace Tests\Feature\Services;

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Events\Identity\BreakGlassExpired;
use SineMacula\Laravel\Authorization\Models\BreakGlassActivation;
use SineMacula\Laravel\Authorization\Services\Support\ExpiredActivations;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\ActivatesBreakGlass;
use Tests\Concerns\ReadsDispatchedEvents;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for recording the expiry of break-glass activations that
 * expired without ending.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExpiredActivations::class)]
final class ExpiredActivationsTest extends TestCase
{
    use ActivatesBreakGlass, ReadsDispatchedEvents;

    /**
     * Start the clock.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow('2026-07-01 12:00:00');
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
     * An activation that expired without ending ends at its expiry, as expired
     * by no one, its row kept, and is reported once with no actor; a live one
     * and one ended already are left, and a second run records nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRecordsTheExpiryOfEachUnendedActivation(): void
    {
        $user    = StubIdentity::query()->create(['id' => 'user-1']);
        $role    = self::emergencyRole();
        $tenant  = new Reference('tenant', 'acct1');
        $expired = self::activate($user, $role, [
            'tenant_type'     => $tenant->type,
            'tenant_id'       => $tenant->id,
            'include_subtree' => false,
            'application'     => 'admin',
            'activated_at'    => Carbon::parse('2026-07-01 11:00:00'),
            'expires_at'      => Carbon::parse('2026-07-01 11:30:00'),
        ]);
        $live  = self::activate($user, $role);
        $ended = self::activate($user, $role, [
            'expires_at'    => Carbon::parse('2026-07-01 11:20:00'),
            'ended_at'      => Carbon::parse('2026-07-01 11:10:00'),
            'ended_by_type' => 'user',
            'ended_by_id'   => 'admin-1',
            'end_reason'    => 'revoked',
        ]);

        Event::fake([BreakGlassExpired::class]);

        self::assertSame(1, ExpiredActivations::record(1000, false));
        self::assertSame(3, BreakGlassActivation::query()->count());
        self::assertSame(['2026-07-01 11:30:00', null, null, 'expired'], self::endOf($expired));
        self::assertSame([null, null, null, null], self::endOf($live));
        self::assertSame(['2026-07-01 11:10:00', 'user', 'admin-1', 'revoked'], self::endOf($ended));

        $events = self::dispatchedEvents(BreakGlassExpired::class);

        self::assertCount(1, $events);
        self::assertEquals(
            [Reference::of($user), Reference::of($role), 'responder', new GrantScope($tenant, 'admin', false), $expired->id, '2026-07-01 11:30:00 UTC'],
            [$events[0]->grantee, $events[0]->role, $events[0]->name, $events[0]->scope, $events[0]->activation, $events[0]->expiredAt->format('Y-m-d H:i:s e')],
        );
        self::assertSame([true, null], [$events[0]->isTrusted(), $events[0]->actor()]);
        self::assertSame(0, ExpiredActivations::record(1000, false));
        Event::assertDispatchedTimes(BreakGlassExpired::class, 1);
    }

    /**
     * Pretending counts the activations a run would record and writes nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testPretendingCountsWithoutWriting(): void
    {
        $user = StubIdentity::query()->create(['id' => 'user-1']);
        $role = self::emergencyRole();

        self::activate($user, $role, ['expires_at' => Carbon::parse('2026-07-01 11:30:00')]);
        self::activate($user, $role, ['expires_at' => Carbon::parse('2026-07-01 12:00:00')]);
        self::activate($user, $role);

        Event::fake([BreakGlassExpired::class]);

        self::assertSame(2, ExpiredActivations::record(1000, true));
        self::assertSame(0, BreakGlassActivation::query()->whereNotNull('ended_at')->count());
        Event::assertNotDispatched(BreakGlassExpired::class);
    }

    /**
     * Each chunk is one operation of its own, and every activation is recorded
     * across them.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEachChunkIsOneOperation(): void
    {
        $user = StubIdentity::query()->create(['id' => 'user-1']);
        $role = self::emergencyRole();

        foreach (['11:00', '11:10', '11:20'] as $at) {
            self::activate($user, $role, ['expires_at' => Carbon::parse('2026-07-01 ' . $at)]);
        }

        Event::fake([BreakGlassExpired::class]);

        self::assertSame(3, ExpiredActivations::record(2, false));

        $operations = \array_map(static fn (BreakGlassExpired $event): string => $event->operationId(), self::dispatchedEvents(BreakGlassExpired::class));

        self::assertCount(3, $operations);
        self::assertSame([2, 1], \array_values(\array_count_values($operations)));
        self::assertSame(0, BreakGlassActivation::query()->whereNull('ended_at')->count());
    }

    /**
     * An activation a surrender or revocation ended after it was read is
     * neither overwritten nor reported nor counted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnActivationEndedMeanwhileIsLeft(): void
    {
        $user       = StubIdentity::query()->create(['id' => 'user-1']);
        $activation = self::activate($user, self::emergencyRole(), ['expires_at' => Carbon::parse('2026-07-01 11:30:00')]);
        $ended      = ['ended_at' => '2026-07-01 11:29:00', 'ended_by_type' => 'user', 'ended_by_id' => 'user-1', 'end_reason' => 'surrendered'];

        /** @var \ArrayObject<int, true> $raced */
        $raced = new \ArrayObject;

        DB::listen(static function (QueryExecuted $query) use ($activation, $ended, $raced): void {
            if ($raced->count() > 0 || !\str_starts_with($query->sql, 'select') || !\str_contains($query->sql, 'break_glass_activations')) {
                return;
            }

            $raced->append(true);

            DB::table('break_glass_activations')->where('id', $activation->id)->update($ended);
        });

        Event::fake([BreakGlassExpired::class]);

        self::assertSame(0, ExpiredActivations::record(1000, false));
        self::assertSame(['2026-07-01 11:29:00', 'user', 'user-1', 'surrendered'], self::endOf($activation));
        Event::assertNotDispatched(BreakGlassExpired::class);
    }

    /**
     * An activation ended meanwhile leaves the rest of its chunk recorded and
     * reported.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheRestOfAChunkIsRecordedPastOneEndedMeanwhile(): void
    {
        $user       = StubIdentity::query()->create(['id' => 'user-1']);
        $role       = self::emergencyRole();
        $ids        = \array_map(static fn (string $at): string => self::activate($user, $role, ['expires_at' => Carbon::parse('2026-07-01 ' . $at)])->id, ['11:30', '11:40']);
        $connection = AuthorizationConnection::connection();

        /** @var \ArrayObject<int, string> $raced */
        $raced = new \ArrayObject;

        $connection->beforeExecuting(static function (string $sql, array $bindings) use ($connection, $raced): void {
            if ($raced->count() > 0 || !\str_starts_with($sql, 'update') || !\str_contains($sql, 'break_glass_activations')) {
                return;
            }

            $raced->append((string) \end($bindings));

            $connection->table('break_glass_activations')->where('id', $raced[0])->update(['ended_at' => '2026-07-01 11:29:00', 'end_reason' => 'surrendered']);
        });

        Event::fake([BreakGlassExpired::class]);

        self::assertSame(1, ExpiredActivations::record(1000, false));

        $events = self::dispatchedEvents(BreakGlassExpired::class);
        $later  = \array_values(\array_diff($ids, [$raced[0]]));

        self::assertCount(1, $events);
        self::assertSame($later, [$events[0]->activation]);
        self::assertSame('expired', BreakGlassActivation::query()->findOrFail($later[0])->end_reason);
        self::assertSame('surrendered', BreakGlassActivation::query()->findOrFail($raced[0])->end_reason);
    }

    /**
     * An activation naming half a tenant is recorded and counted but reported
     * by no event; a platform-wide one beside it is reported, reaching below.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAHalfTenantIsRecordedWithNoEvent(): void
    {
        $user     = StubIdentity::query()->create(['id' => 'user-1']);
        $role     = self::emergencyRole();
        $half     = self::activate($user, $role, ['tenant_type' => 'tenant', 'tenant_id' => null, 'expires_at' => Carbon::parse('2026-07-01 11:30:00')]);
        $platform = self::activate($user, $role, ['expires_at' => Carbon::parse('2026-07-01 11:40:00')]);

        Event::fake([BreakGlassExpired::class]);

        self::assertSame(2, ExpiredActivations::record(1000, false));
        self::assertSame(['2026-07-01 11:30:00', null, null, 'expired'], self::endOf($half));

        $events = self::dispatchedEvents(BreakGlassExpired::class);

        self::assertCount(1, $events);
        self::assertSame($platform->id, $events[0]->activation);
        self::assertEquals(new GrantScope(null, null, true), $events[0]->scope);
    }

    /**
     * Return how the activation ended, as stored: when, by whom and why.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\BreakGlassActivation  $activation
     * @return list<string|null>
     */
    private static function endOf(BreakGlassActivation $activation): array
    {
        $stored = BreakGlassActivation::query()->findOrFail($activation->id);

        return [$stored->ended_at?->toDateTimeString(), $stored->ended_by_type, $stored->ended_by_id, $stored->end_reason];
    }
}
