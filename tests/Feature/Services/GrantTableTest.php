<?php

declare(strict_types = 1);

namespace Tests\Feature\Services;

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Enums\GrantOutcome;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\Support\GrantChange;
use SineMacula\Laravel\Authorization\Services\Support\GrantTable;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\RecordsRowLocks;
use Tests\TestCase;

/**
 * Feature tests for `GrantTable`, the grant rows one grantee holds in one grant
 * table.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(GrantTable::class)]
#[CoversClass(GrantChange::class)]
final class GrantTableTest extends TestCase
{
    use RecordsRowLocks;

    /** @var string The instant every test starts at. */
    private const string NOW = '2026-07-01 12:00:00';

    /** @var array<string, array<string, string>> Rows that differ from the platform-wide row in one scope column only. */
    private const array SCOPED_ROWS = [
        'tenant type only' => ['tenant_type' => 'stub_tenant', 'expires_at' => '2026-07-03 12:00:00'],
        'tenant id only'   => ['tenant_id' => 'tenant-a', 'expires_at' => '2026-07-04 12:00:00'],
        'application only' => ['application' => 'admin', 'expires_at' => '2026-07-05 12:00:00'],
    ];

    /**
     * Freeze the clock.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow(self::NOW);
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
     * A grant the grantee does not hold inserts one platform-wide row for every
     * application, with the expiry in UTC and the grant's timestamps.
     *
     * @return void
     */
    public function testAGrantNotHeldInsertsAPlatformWideRow(): void
    {
        $role = self::role();

        $change = self::table()->grant($role->id, Carbon::parse('2026-07-01 14:00:00', 'Europe/London'));

        self::assertSame(GrantOutcome::GRANTED, $change->outcome);
        self::assertNull($change->previousExpiresAt);
        self::assertSame([[
            'role_id'           => $role->id,
            'authorizable_type' => 'stub_identity',
            'authorizable_id'   => 'user-1',
            'tenant_type'       => null,
            'tenant_id'         => null,
            'application'       => null,
            'expires_at'        => '2026-07-01 13:00:00',
            'created_at'        => self::NOW,
            'updated_at'        => self::NOW,
        ]], self::rows());
    }

    /**
     * A grant in a tenant is written with its reach: the tenants below it as
     * well by default, or the tenant alone.
     *
     * @return void
     */
    public function testAGrantIsWrittenWithItsReach(): void
    {
        $role  = self::role();
        $other = self::role('viewer');

        (new GrantTable(DB::connection(), 'authorizable_roles', 'role_id', 'stub_identity', 'user-1', null, self::tenant()))->grant($role->id, null);
        self::table(tenant: self::tenant(), includeSubtree: false)->grant($other->id, null);

        self::assertEquals([$role->id => true, $other->id => false], self::reaches());
    }

    /**
     * Granting what is held with the same expiry and another reach changes the
     * reach alone, reported with the expiry held, and records the actor; the
     * same reach again changes nothing.
     *
     * @return void
     */
    public function testAnotherReachOnAHeldGrantChangesTheReach(): void
    {
        $role  = self::role();
        $actor = new Reference('stub_identity', 'admin');

        self::table(tenant: self::tenant())->grant($role->id, Carbon::parse('2026-07-02 12:00:00'));

        Carbon::setTestNow('2026-07-01 12:30:00');

        $change = self::table(grantedBy: $actor, tenant: self::tenant(), includeSubtree: false)->grant($role->id, Carbon::parse('2026-07-02 12:00:00'));

        self::assertSame(GrantOutcome::REACH_CHANGED, $change->outcome);
        self::assertSame('2026-07-02 12:00:00', $change->previousExpiresAt?->format('Y-m-d H:i:s'));
        self::assertEquals([$role->id => false], self::reaches());
        self::assertSame(['2026-07-02 12:00:00'], self::expiries());
        self::assertSame('2026-07-01 12:30:00', self::rows()[0]['updated_at']);
        self::assertSame([[$role->id, 'stub_identity', 'admin']], self::grantors());
        self::assertSame(GrantOutcome::UNCHANGED, self::table(tenant: self::tenant(), includeSubtree: false)->grant($role->id, Carbon::parse('2026-07-02 12:00:00'))->outcome);
    }

    /**
     * A changed expiry, or a re-armed grant, is written with the writer's
     * reach; a re-arm leaves a live grant's reach as it is.
     *
     * @return void
     */
    public function testARewriteCarriesTheReach(): void
    {
        $role    = self::role();
        $expired = self::role('viewer');
        $live    = self::role('author');
        $table   = self::table(tenant: self::tenant());
        $limited = self::table(tenant: self::tenant(), includeSubtree: false);

        $table->grant($role->id, null);
        $table->grant($expired->id, Carbon::parse(self::NOW));
        $table->grant($live->id, null);

        self::assertSame(GrantOutcome::EXPIRY_CHANGED, $limited->grant($role->id, Carbon::parse('2026-07-02 12:00:00'))->outcome);
        self::assertSame(GrantOutcome::REARMED, $limited->rearm($expired->id, null)->outcome);
        self::assertSame(GrantOutcome::UNCHANGED, $limited->rearm($live->id, null)->outcome);
        self::assertEquals([$role->id => false, $expired->id => false, $live->id => true], self::reaches());
    }

    /**
     * The reach of each held row in the scope is read by key, and a row in
     * another scope or not held is left out.
     *
     * @return void
     */
    public function testReachesReadEachHeldRowInTheScope(): void
    {
        $role    = self::role();
        $other   = self::role('viewer');
        $outside = self::role('author');

        self::table(tenant: self::tenant())->grant($role->id, null);
        self::table(tenant: self::tenant(), includeSubtree: false)->grant($other->id, null);
        self::table()->grant($outside->id, null);

        $reaches  = self::table(tenant: self::tenant())->reaches([$role->id, $other->id, $outside->id]);
        $expected = [$role->id => true, $other->id => false];

        \ksort($reaches);
        \ksort($expected);

        self::assertSame($expected, $reaches);
        self::assertSame([], self::table(tenant: self::tenant())->reaches([]));
    }

    /**
     * A grant for an application is written for it and is a grant apart from
     * the one for every application; the grants of every scope report it.
     *
     * @return void
     */
    public function testAGrantForAnApplicationIsAGrantApart(): void
    {
        $role   = self::role();
        $admin  = new GrantTable(DB::connection(), 'authorizable_roles', 'role_id', 'stub_identity', 'user-1', null, null, true, 'admin');
        $every  = self::table();
        $mobile = new GrantTable(DB::connection(), 'authorizable_roles', 'role_id', 'stub_identity', 'user-1', null, null, true, 'mobile');

        self::assertSame(GrantOutcome::GRANTED, $admin->grant($role->id, null)->outcome);
        self::assertSame(GrantOutcome::GRANTED, $every->grant($role->id, null)->outcome);
        self::assertSame(GrantOutcome::UNCHANGED, $admin->grant($role->id, null)->outcome);
        self::assertSame([], $mobile->held());
        self::assertSame([$role->id], $admin->held());

        $admin->revoke([$role->id]);

        self::assertEquals([[$role->id, new GrantScope]], self::table()->grantsInEveryScope());
        self::assertEqualsCanonicalizing([null], DB::table('authorizable_roles')->pluck('application')->all());

        $mobile->grant($role->id, null);

        self::assertEquals([[$role->id, new GrantScope], [$role->id, new GrantScope(null, 'mobile')]], self::sortedGrants());
    }

    /**
     * Granting what is held with the same expiry changes nothing, the same
     * instant in another zone included.
     *
     * @return void
     */
    public function testGrantingWhatIsHeldWithTheSameExpiryChangesNothing(): void
    {
        $role  = self::role();
        $table = self::table();

        $table->grant($role->id, Carbon::parse('2026-07-01 13:00:00', 'UTC'));

        Carbon::setTestNow('2026-07-01 12:30:00');

        $change = $table->grant($role->id, Carbon::parse('2026-07-01 14:00:00', 'Europe/London'));

        self::assertSame(GrantOutcome::UNCHANGED, $change->outcome);
        self::assertSame('2026-07-01 13:00:00', $change->previousExpiresAt?->format('Y-m-d H:i:s'));
        self::assertSame(self::NOW, self::rows()[0]['updated_at']);
    }

    /**
     * Granting a forever grant again changes nothing.
     *
     * @return void
     */
    public function testGrantingAForeverGrantAgainChangesNothing(): void
    {
        $role  = self::role();
        $table = self::table();

        $table->grant($role->id, null);

        $change = $table->grant($role->id, null);

        self::assertSame(GrantOutcome::UNCHANGED, $change->outcome);
        self::assertNull($change->previousExpiresAt);
        self::assertCount(1, self::rows());
    }

    /**
     * A different expiry on a live grant is written and reported as a changed
     * expiry, with the previous one.
     *
     * @return void
     */
    public function testADifferentExpiryOnALiveGrantIsAChangedExpiry(): void
    {
        $role  = self::role();
        $table = self::table();

        $table->grant($role->id, Carbon::parse('2026-07-01 13:00:00', 'UTC'));

        Carbon::setTestNow('2026-07-01 12:30:00');

        $change = $table->grant($role->id, Carbon::parse('2026-07-02 13:00:00', 'UTC'));

        self::assertSame(GrantOutcome::EXPIRY_CHANGED, $change->outcome);
        self::assertSame('2026-07-01 13:00:00', $change->previousExpiresAt?->format('Y-m-d H:i:s'));
        self::assertSame('2026-07-02 13:00:00', self::rows()[0]['expires_at']);
        self::assertSame('2026-07-01 12:30:00', self::rows()[0]['updated_at']);
        self::assertSame(self::NOW, self::rows()[0]['created_at']);
    }

    /**
     * Making an expiring grant forever, or a forever grant expiring, is a
     * changed expiry.
     *
     * @return void
     */
    public function testSwitchingBetweenForeverAndAnExpiryIsAChangedExpiry(): void
    {
        $role  = self::role();
        $table = self::table();

        $table->grant($role->id, Carbon::parse('2026-07-01 13:00:00', 'UTC'));

        self::assertSame(GrantOutcome::EXPIRY_CHANGED, $table->grant($role->id, null)->outcome);
        self::assertNull(self::rows()[0]['expires_at']);

        $change = $table->grant($role->id, Carbon::parse('2026-07-01 15:00:00', 'UTC'));

        self::assertSame(GrantOutcome::EXPIRY_CHANGED, $change->outcome);
        self::assertNull($change->previousExpiresAt);
        self::assertSame('2026-07-01 15:00:00', self::rows()[0]['expires_at']);
    }

    /**
     * Granting again a grant that has expired re-arms it with the new expiry. A
     * grant whose expiry is exactly now has expired.
     *
     * @return void
     */
    public function testRegrantingAnExpiredGrantReArmsIt(): void
    {
        $role  = self::role();
        $table = self::table();

        $table->grant($role->id, Carbon::parse('2026-07-01 13:00:00', 'UTC'));

        Carbon::setTestNow('2026-07-01 13:00:00');

        $change = $table->grant($role->id, null);

        self::assertSame(GrantOutcome::REARMED, $change->outcome);
        self::assertSame('2026-07-01 13:00:00', $change->previousExpiresAt?->format('Y-m-d H:i:s'));
        self::assertNull(self::rows()[0]['expires_at']);
    }

    /**
     * A row written by another transaction, as a concurrent duplicate would be,
     * is read back rather than raising a unique-constraint violation.
     *
     * @return void
     */
    public function testARowAnotherWriterHoldsIsReadBackRatherThanRaising(): void
    {
        $role = self::role();

        self::insertRow($role->id, []);

        self::assertSame(GrantOutcome::UNCHANGED, self::table()->grant($role->id, null)->outcome);
        self::assertCount(1, self::rows());
    }

    /**
     * A row in a tenant or application scope is not the platform-wide grant, so
     * granting writes the platform-wide row beside it and leaves it as it is.
     *
     * @return void
     */
    public function testAScopedRowIsNotThePlatformWideGrant(): void
    {
        $role = self::role();

        self::insertRow($role->id, ['tenant_type' => 'stub_tenant', 'tenant_id' => 'tenant-a', 'expires_at' => '2026-07-01 13:00:00']);
        self::insertRow($role->id, ['application' => 'admin', 'expires_at' => '2026-07-01 13:00:00']);

        self::assertSame(GrantOutcome::GRANTED, self::table()->grant($role->id, null)->outcome);
        self::assertSame(2, DB::table('authorizable_roles')->where('expires_at', '2026-07-01 13:00:00')->count());
        self::assertSame(1, DB::table('authorizable_roles')->whereNull('expires_at')->whereNull('tenant_type')->whereNull('application')->count());
    }

    /**
     * Granting a held grant again reads back and rewrites only the
     * platform-wide row, never a row scoped by one column, and reports the
     * platform-wide row's expiry as the previous one.
     *
     * @return void
     */
    public function testARegrantReadsAndRewritesOnlyThePlatformWideRow(): void
    {
        $role = self::role();

        self::insertRow($role->id, ['expires_at' => '2026-07-02 12:00:00']);

        foreach (self::SCOPED_ROWS as $columns) {
            self::insertRow($role->id, $columns);
        }

        $change = self::table()->grant($role->id, Carbon::parse('2026-07-06 12:00:00', 'UTC'));

        self::assertSame(GrantOutcome::EXPIRY_CHANGED, $change->outcome);
        self::assertSame('2026-07-02 12:00:00', $change->previousExpiresAt?->format('Y-m-d H:i:s'));
        self::assertSame(['2026-07-03 12:00:00', '2026-07-04 12:00:00', '2026-07-05 12:00:00', '2026-07-06 12:00:00'], self::expiries());
    }

    /**
     * Re-arming an expired grant reads back and rewrites only the platform-wide
     * row, never a row scoped by one column.
     *
     * @return void
     */
    public function testARearmReadsAndRewritesOnlyThePlatformWideRow(): void
    {
        $role = self::role();

        self::insertRow($role->id, ['expires_at' => '2026-07-01 11:00:00']);

        foreach (self::SCOPED_ROWS as $columns) {
            self::insertRow($role->id, $columns);
        }

        $change = self::table()->rearm($role->id, Carbon::parse('2026-07-06 12:00:00', 'UTC'));

        self::assertSame(GrantOutcome::REARMED, $change->outcome);
        self::assertSame('2026-07-01 11:00:00', $change->previousExpiresAt?->format('Y-m-d H:i:s'));
        self::assertSame(['2026-07-03 12:00:00', '2026-07-04 12:00:00', '2026-07-05 12:00:00', '2026-07-06 12:00:00'], self::expiries());
    }

    /**
     * A held grant's expiry, and then its reach, are read back under a row lock
     * on the grant table.
     *
     * @return void
     */
    public function testAHeldGrantIsReadBackUnderARowLock(): void
    {
        $role  = self::role();
        $table = self::table();

        $table->grant($role->id, null);

        $locks = $this->recordRowLocks();

        $table->grant($role->id, null);

        self::assertSame([
            ['authorizable_roles', ['stub_identity', 'user-1', $role->id]],
            ['authorizable_roles', ['stub_identity', 'user-1', $role->id]],
        ], $locks->getArrayCopy());
    }

    /**
     * Another grantee's row is neither read nor changed.
     *
     * @return void
     */
    public function testAnotherGranteesRowIsNotRead(): void
    {
        $role = self::role();

        self::table('user-2')->grant($role->id, Carbon::parse('2026-07-01 13:00:00', 'UTC'));

        self::assertSame(GrantOutcome::GRANTED, self::table()->grant($role->id, null)->outcome);
        $expiries = \array_column(self::rows(), 'expires_at', 'authorizable_id');

        \ksort($expiries);

        self::assertSame(['user-1' => null, 'user-2' => '2026-07-01 13:00:00'], $expiries);
    }

    /**
     * Another type's row with the same key is neither read nor changed.
     *
     * @return void
     */
    public function testAnotherTypesRowIsNotRead(): void
    {
        $role = self::role();

        (new GrantTable(DB::connection(), 'authorizable_roles', 'role_id', 'stub_second_identity', 'user-1'))->grant($role->id, null);

        self::assertSame(GrantOutcome::GRANTED, self::table()->grant($role->id, null)->outcome);
        self::assertSame([], self::table()->held([]));
        self::assertSame([$role->id], self::table()->held());
    }

    /**
     * Re-arming a grant that is not held grants it.
     *
     * @return void
     */
    public function testRearmingWhatIsNotHeldGrantsIt(): void
    {
        $role = self::role();

        $change = self::table()->rearm($role->id, Carbon::parse('2026-07-01 13:00:00', 'UTC'));

        self::assertSame(GrantOutcome::GRANTED, $change->outcome);
        self::assertSame('2026-07-01 13:00:00', self::rows()[0]['expires_at']);
    }

    /**
     * Re-arming leaves a live grant as it is, whatever expiry it is given.
     *
     * @return void
     */
    public function testRearmingLeavesALiveGrantAsItIs(): void
    {
        $role  = self::role();
        $table = self::table();

        $table->grant($role->id, Carbon::parse('2026-07-01 13:00:00', 'UTC'));

        $change = $table->rearm($role->id, null);

        self::assertSame(GrantOutcome::UNCHANGED, $change->outcome);
        self::assertSame('2026-07-01 13:00:00', $change->previousExpiresAt?->format('Y-m-d H:i:s'));
        self::assertSame('2026-07-01 13:00:00', self::rows()[0]['expires_at']);
    }

    /**
     * Re-arming leaves a forever grant as it is.
     *
     * @return void
     */
    public function testRearmingLeavesAForeverGrantAsItIs(): void
    {
        $role  = self::role();
        $table = self::table();

        $table->grant($role->id, null);

        self::assertSame(GrantOutcome::UNCHANGED, $table->rearm($role->id, Carbon::parse('2026-07-01 13:00:00', 'UTC'))->outcome);
        self::assertNull(self::rows()[0]['expires_at']);
    }

    /**
     * Re-arming a grant that has expired writes the new expiry.
     *
     * @return void
     */
    public function testRearmingAnExpiredGrantWritesTheNewExpiry(): void
    {
        $role  = self::role();
        $table = self::table();

        $table->grant($role->id, Carbon::parse('2026-07-01 13:00:00', 'UTC'));

        Carbon::setTestNow('2026-07-01 14:00:00');

        $change = $table->rearm($role->id, Carbon::parse('2026-07-02 14:00:00', 'UTC'));

        self::assertSame(GrantOutcome::REARMED, $change->outcome);
        self::assertSame('2026-07-01 13:00:00', $change->previousExpiresAt?->format('Y-m-d H:i:s'));
        self::assertSame('2026-07-02 14:00:00', self::rows()[0]['expires_at']);
        self::assertSame('2026-07-01 14:00:00', self::rows()[0]['updated_at']);
    }

    /**
     * Re-arming an expired grant with the expiry it already carries changes
     * nothing.
     *
     * @return void
     */
    public function testRearmingAnExpiredGrantWithItsOwnExpiryChangesNothing(): void
    {
        $role  = self::role();
        $table = self::table();

        $table->grant($role->id, Carbon::parse('2026-07-01 13:00:00', 'UTC'));

        Carbon::setTestNow('2026-07-01 14:00:00');

        self::assertSame(GrantOutcome::UNCHANGED, $table->rearm($role->id, Carbon::parse('2026-07-01 13:00:00', 'UTC'))->outcome);
        self::assertSame(self::NOW, self::rows()[0]['updated_at']);
    }

    /**
     * `held()` lists each key the grantee holds once, in any scope and whether
     * or not it has expired; given keys, only those among them.
     *
     * @return void
     */
    public function testHeldListsEachHeldKeyOnce(): void
    {
        $first  = self::role('first');
        $second = self::role('second');
        $third  = self::role('third');
        $table  = self::table();

        $table->grant($first->id, Carbon::parse('2026-07-01 11:00:00', 'UTC'));
        $table->grant($second->id, null);

        self::insertRow($first->id, ['tenant_type' => 'stub_tenant', 'tenant_id' => 'tenant-a']);

        $held = $table->held();

        \sort($held);

        $expected = [$first->id, $second->id];

        \sort($expected);

        self::assertSame($expected, $held);
        self::assertSame([$second->id], $table->held([$second->id, $third->id]));
    }

    /**
     * `revoke()` deletes the grantee's rows for the given keys in its scope,
     * and nothing else: a grant in a tenant stays.
     *
     * @return void
     */
    public function testRevokeDeletesTheGranteesRowsForTheKeysInItsScope(): void
    {
        $first  = self::role('first');
        $second = self::role('second');
        $table  = self::table();

        $table->grant($first->id, null);
        $table->grant($second->id, null);
        self::table('user-2')->grant($first->id, null);
        self::table(tenant: self::tenant())->grant($first->id, null);

        $table->revoke([$first->id]);

        self::assertSame([$second->id], $table->held());
        self::assertSame([$first->id], self::table('user-2')->held());
        self::assertSame([$first->id], self::table(tenant: self::tenant())->held());
    }

    /**
     * A grant in a tenant writes the tenant columns, and is held, re-granted
     * and revoked in that tenant only.
     *
     * @return void
     */
    public function testAGrantInATenantIsHeldThereOnly(): void
    {
        $role   = self::role();
        $scoped = self::table(tenant: self::tenant());

        self::assertSame(GrantOutcome::GRANTED, $scoped->grant($role->id, null)->outcome);
        $scopes = DB::table('authorizable_roles')->get(['tenant_type', 'tenant_id'])->map(static fn (object $row): array => [$row->tenant_type, $row->tenant_id]);

        self::assertSame([['stub_tenant', 'tenant-a']], $scopes->all());
        self::assertSame([$role->id], $scoped->held());
        self::assertSame([], self::table()->held());
        self::assertSame([], self::table(tenant: new Reference('stub_tenant', 'tenant-b'))->held());

        self::assertSame(GrantOutcome::EXPIRY_CHANGED, $scoped->grant($role->id, Carbon::parse('2026-07-02 12:00:00', 'UTC'))->outcome);
        self::assertSame(GrantOutcome::GRANTED, self::table()->grant($role->id, null)->outcome);
        $format   = static fn (mixed $value): ?string => $value === null ? null : Carbon::parse((string) $value)->format('Y-m-d H:i:s'); // @phpstan-ignore cast.string
        $expiries = [];

        foreach (DB::table('authorizable_roles')->get(['tenant_id', 'expires_at']) as $row) {
            $expiries[$row->tenant_id ?? 'platform'] = $format($row->expires_at);
        }

        \ksort($expiries);

        self::assertSame(['platform' => null, 'tenant-a' => '2026-07-02 12:00:00'], $expiries);

        $scoped->revoke([$role->id]);

        self::assertSame([], $scoped->held());
        self::assertSame([$role->id], self::table()->held());
    }

    /**
     * Every grant the grantee holds is listed with its tenant and revoked
     * together, in every scope, leaving other grantees' grants.
     *
     * @return void
     */
    public function testEveryScopeIsReadAndRevokedTogether(): void
    {
        $first  = self::role('first');
        $second = self::role('second');

        self::table()->grant($first->id, null);
        self::table(tenant: self::tenant(), includeSubtree: false)->grant($second->id, null);
        self::table('user-2')->grant($first->id, null);

        $grants = self::table()->grantsInEveryScope();

        \usort($grants, static fn (array $left, array $right): int => $left[0] <=> $right[0]);

        $expected = [[$first->id, new GrantScope], [$second->id, new GrantScope(self::tenant(), null, false)]];

        \usort($expected, static fn (array $left, array $right): int => $left[0] <=> $right[0]);

        self::assertEquals($expected, $grants);

        self::table()->revokeInEveryScope();

        self::assertSame([], self::table()->grantsInEveryScope());
        self::assertSame([$first->id], self::table('user-2')->held());
    }

    /**
     * A grant records the actor making it in the grantor columns, and none when
     * the call names no actor.
     *
     * @return void
     */
    public function testAGrantRecordsItsActor(): void
    {
        $role  = self::role();
        $other = self::role('author');

        self::table(grantedBy: new Reference('user', 'admin-1'))->grant($role->id, null);
        self::table()->grant($other->id, null);

        self::assertSame([
            [$other->id, null, null],
            [$role->id, 'user', 'admin-1'],
        ], self::grantors());
    }

    /**
     * Rewriting a grant's expiry records the actor making the change, in place
     * of the one that made the grant.
     *
     * @return void
     */
    public function testARewriteRecordsItsActor(): void
    {
        $role = self::role();

        self::table(grantedBy: new Reference('user', 'admin-1'))->grant($role->id, Carbon::parse('2026-07-02 12:00:00', 'UTC'));
        self::table(grantedBy: new Reference('user', 'admin-2'))->grant($role->id, Carbon::parse('2026-07-03 12:00:00', 'UTC'));

        self::assertSame([[$role->id, 'user', 'admin-2']], self::grantors());

        self::table()->grant($role->id, null);

        self::assertSame([[$role->id, null, null]], self::grantors());
    }

    /**
     * The live rows are those held in the scope, among the given ones, whose
     * grant has not expired: one that expires later is live, one that has
     * expired is not, and one not asked about is not read.
     *
     * @return void
     */
    public function testTheLiveRowsAreTheHeldOnesNotYetExpired(): void
    {
        $forever = Role::create(['name' => 'forever']);
        $later   = Role::create(['name' => 'later']);
        $expired = Role::create(['name' => 'expired']);
        $unasked = Role::create(['name' => 'unasked']);
        $table   = self::table();

        $table->grant($forever->id, null);
        $table->grant($later->id, Carbon::parse(self::NOW)->addDay());
        $table->grant($expired->id, Carbon::parse(self::NOW)->subDay());
        $table->grant($unasked->id, null);
        self::table('user-2')->grant($forever->id, null);

        $live = $table->live([$forever->id, $later->id, $expired->id]);

        \sort($live);

        $expected = [$forever->id, $later->id];

        \sort($expected);

        self::assertSame($expected, $live);
        self::assertSame([], self::table(tenant: self::tenant())->live([$forever->id]));
        self::assertSame([], $table->live([]));
        self::assertSame([$forever->id], $table->live([$forever->id, $later->id], Carbon::parse(self::NOW)->addDays(2)));
    }

    /**
     * Return a grant table writer for a stub identity's roles, recording the
     * given actor on the rows it writes.
     *
     * @param  string  $granteeId
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $grantedBy
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  bool  $includeSubtree
     * @return \SineMacula\Laravel\Authorization\Services\Support\GrantTable
     */
    private static function table(string $granteeId = 'user-1', ?Reference $grantedBy = null, ?Reference $tenant = null, bool $includeSubtree = true): GrantTable
    {
        return new GrantTable(DB::connection(), 'authorizable_roles', 'role_id', 'stub_identity', $granteeId, $grantedBy, $tenant, $includeSubtree);
    }

    /**
     * Return whether each role grant row reaches the tenants below its tenant,
     * keyed by the role.
     *
     * @return array<string, bool>
     */
    private static function reaches(): array
    {
        $reaches = [];

        foreach (DB::table('authorizable_roles')->get(['role_id', 'include_subtree']) as $row) {
            $reaches[(string) $row->role_id] = (bool) $row->include_subtree; // @phpstan-ignore cast.string
        }

        return $reaches;
    }

    /**
     * Return the tenant scoped grants are made in.
     *
     * @return \SineMacula\Laravel\Authorization\Support\Reference
     */
    private static function tenant(): Reference
    {
        return new Reference('stub_tenant', 'tenant-a');
    }

    /**
     * Return the role and grantor columns of every role grant row, ordered by
     * the grantor.
     *
     * @return list<array{string, string|null, string|null}>
     */
    private static function grantors(): array
    {
        // Sorted here rather than by the database, which orders nulls first on
        // MySQL and SQLite but last on PostgreSQL.
        /** @var list<array{string, string|null, string|null}> */
        return DB::table('authorizable_roles')
            ->get(['role_id', 'granted_by_type', 'granted_by_id'])
            ->map(static fn (object $row): array => \array_values((array) $row))
            ->sortBy(static fn (array $row): string => (string) $row[2])
            ->values()
            ->all();
    }

    /**
     * Create a role.
     *
     * @param  string  $name
     * @return \SineMacula\Laravel\Authorization\Models\Role
     */
    private static function role(string $name = 'editor'): Role
    {
        return Role::query()->create(['name' => $name]);
    }

    /**
     * Insert a role grant row for the stub identity directly, as another writer
     * would, with the given columns.
     *
     * @param  string  $roleId
     * @param  array<string, string|null>  $columns
     * @return void
     */
    private static function insertRow(string $roleId, array $columns): void
    {
        DB::table('authorizable_roles')->insert([
            'role_id'           => $roleId,
            'authorizable_type' => 'stub_identity',
            'authorizable_id'   => 'user-1',
            ...$columns,
        ]);
    }

    /**
     * Return the expiry of every role grant row, in order.
     *
     * @return list<string|null>
     */
    private static function expiries(): array
    {
        /** @var list<string|null> */
        return DB::table('authorizable_roles')->orderBy('expires_at')->pluck('expires_at')->all();
    }

    /**
     * Return every role grant row, without the subtree flag or the grantor.
     *
     * @return list<array<string, mixed>>
     */
    private static function rows(): array
    {
        /** @var list<array<string, mixed>> */
        return DB::table('authorizable_roles')
            ->get(['role_id', 'authorizable_type', 'authorizable_id', 'tenant_type', 'tenant_id', 'application', 'expires_at', 'created_at', 'updated_at'])
            ->map(static fn (object $row): array => (array) $row)
            ->all();
    }

    /**
     * Return the grants of every scope the stub identity holds, those for every
     * application first.
     *
     * @return list<array{0: string, 1: \SineMacula\Laravel\Authorization\Support\GrantScope}>
     */
    private static function sortedGrants(): array
    {
        $grants = self::table()->grantsInEveryScope();

        \usort($grants, static fn (array $left, array $right): int => (string) $left[1]->application <=> (string) $right[1]->application);

        return $grants;
    }
}
