<?php

declare(strict_types = 1);

namespace Tests\Feature\Services;

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\QueryException;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Enums\GrantOutcome;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\Support\ExpiringGrants;
use SineMacula\Laravel\Authorization\Services\Support\GrantChanges;
use SineMacula\Laravel\Authorization\Services\Support\RolePermissionTable;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\InterleavesWrites;
use Tests\TestCase;

/**
 * Feature tests for what a grant with an optional expiry changes, through the
 * role permission writer: a new grant, the same expiry, a changed expiry and a
 * re-armed grant, for a grant and for a sync's re-arm.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExpiringGrants::class)]
final class ExpiringGrantsTest extends TestCase
{
    use InterleavesWrites;

    /** @var string The instant every test starts at. */
    private const string NOW = '2026-07-01 12:00:00';

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
     * A grant not held stores the row with its expiry, in UTC.
     *
     * @return void
     */
    public function testAGrantNotHeldStoresTheRow(): void
    {
        [$table, $permission] = self::grants();

        $change = $table->grant($permission->id, Carbon::parse('2026-07-02 14:00:00', 'Europe/Paris'));

        self::assertSame(GrantOutcome::GRANTED, $change?->outcome);
        self::assertNull($change->previousExpiresAt);
        self::assertSame(['2026-07-02 12:00:00'], self::expiries());
    }

    /**
     * Granting what is held with the same expiry, or forever again, changes
     * nothing and reports the expiry held.
     *
     * @return void
     */
    public function testTheSameExpiryChangesNothing(): void
    {
        [$table, $permission, $other] = self::grants();

        $table->grant($permission->id, Carbon::parse('2026-07-02 12:00:00'));
        $table->grant($other->id, null);

        $same    = $table->grant($permission->id, Carbon::parse('2026-07-02 14:00:00', 'Europe/Paris'));
        $forever = $table->grant($other->id, null);

        self::assertSame(GrantOutcome::UNCHANGED, $same?->outcome);
        self::assertSame('2026-07-02 12:00:00', $same->previousExpiresAt?->format('Y-m-d H:i:s'));
        self::assertSame(GrantOutcome::UNCHANGED, $forever?->outcome);
        self::assertNull($forever->previousExpiresAt);
    }

    /**
     * A live grant given another expiry, or switched between forever and an
     * expiry, has its expiry changed and reports the one it replaced.
     *
     * @return void
     */
    public function testADifferentExpiryOnALiveGrantChangesIt(): void
    {
        [$table, $permission] = self::grants();

        $table->grant($permission->id, Carbon::parse('2026-07-02 12:00:00'));

        $later   = $table->grant($permission->id, Carbon::parse('2026-07-03 12:00:00'));
        $forever = $table->grant($permission->id, null);
        $dated   = $table->grant($permission->id, Carbon::parse('2026-07-04 12:00:00'));

        self::assertSame(GrantOutcome::EXPIRY_CHANGED, $later?->outcome);
        self::assertSame('2026-07-02 12:00:00', $later->previousExpiresAt?->format('Y-m-d H:i:s'));
        self::assertSame(GrantOutcome::EXPIRY_CHANGED, $forever?->outcome);
        self::assertSame(GrantOutcome::EXPIRY_CHANGED, $dated?->outcome);
        self::assertNull($dated->previousExpiresAt);
        self::assertNull($dated->previousReach);
        self::assertSame(['2026-07-04 12:00:00'], self::expiries());
    }

    /**
     * A write of a held row reports the reach its table read with the expiry,
     * whether it rewrote the row or left it; a stored row reports none.
     *
     * @return void
     */
    public function testAWriteOfAHeldRowReportsTheReachItsTableRead(): void
    {
        $role  = Role::query()->create(['name' => 'editor']);
        $table = GrantChanges::table(GrantTarget::ROLE, new Reference('user', '1'), null, new GrantScope(new Reference('tenant', 'a'), null, false));

        self::assertNull($table->grant($role->id, Carbon::parse(self::NOW))?->previousReach);
        self::assertFalse($table->grant($role->id, null)?->previousReach);
        self::assertFalse($table->grant($role->id, null)->previousReach);
        self::assertFalse($table->rearm($role->id, Carbon::parse(self::NOW)->addDay(), Carbon::parse(self::NOW))?->previousReach);
    }

    /**
     * A grant whose expiry has passed, the current instant included, is
     * re-armed with the new expiry.
     *
     * @return void
     */
    public function testAnExpiredGrantIsReArmed(): void
    {
        [$table, $permission] = self::grants();

        $table->grant($permission->id, Carbon::parse(self::NOW));

        $change = $table->grant($permission->id, null);

        self::assertSame(GrantOutcome::REARMED, $change?->outcome);
        self::assertSame(self::NOW, $change->previousExpiresAt?->format('Y-m-d H:i:s'));
        self::assertSame([null], self::expiries());
    }

    /**
     * A re-arm grants what is not held, leaves a live or forever grant as it
     * is, and writes the new expiry only to a grant that has expired.
     *
     * @return void
     */
    public function testARearmWritesOnlyAnExpiredGrant(): void
    {
        [$table, $permission, $other] = self::grants();
        $missing                      = Permission::query()->create(['name' => 'posts:create']);

        $table->grant($permission->id, Carbon::parse('2026-07-02 12:00:00'));
        $table->grant($other->id, null);

        self::assertSame(GrantOutcome::GRANTED, $table->rearm($missing->id, null)?->outcome);
        self::assertSame(GrantOutcome::UNCHANGED, $table->rearm($permission->id, Carbon::parse('2026-07-09 12:00:00'))?->outcome);
        self::assertSame(GrantOutcome::UNCHANGED, $table->rearm($other->id, Carbon::parse('2026-07-09 12:00:00'))?->outcome);

        Carbon::setTestNow('2026-07-02 12:00:00');

        $rearmed = $table->rearm($permission->id, Carbon::parse('2026-07-09 12:00:00'));

        self::assertSame(GrantOutcome::REARMED, $rearmed->outcome);
        self::assertSame('2026-07-02 12:00:00', $rearmed->previousExpiresAt?->format('Y-m-d H:i:s'));
        self::assertSame('2026-07-09 12:00:00', DB::table('role_permissions')->where('permission_id', $permission->id)->value('expires_at'));
    }

    /**
     * A re-arm judges whether a grant has expired at the instant it is given,
     * not by the clock: a grant live then is left as it is though the clock has
     * passed its expiry, one that expired by then, its expiry at that instant
     * included, is re-armed though the clock has not reached it.
     *
     * @return void
     */
    public function testARearmJudgesExpiryAtTheInstantGiven(): void
    {
        [$table, $permission, $other] = self::grants();

        $table->grant($permission->id, Carbon::parse('2026-07-01 11:00:00'));
        $table->grant($other->id, Carbon::parse('2026-07-01 13:00:00'));

        self::assertSame(GrantOutcome::UNCHANGED, $table->rearm($permission->id, null, Carbon::parse('2026-07-01 10:00:00'))?->outcome);
        self::assertSame(GrantOutcome::REARMED, $table->rearm($other->id, null, Carbon::parse('2026-07-01 13:00:00'))?->outcome);
        self::assertSame('2026-07-01 11:00:00', DB::table('role_permissions')->where('permission_id', $permission->id)->value('expires_at'));
        self::assertNull(DB::table('role_permissions')->where('permission_id', $other->id)->value('expires_at'));
    }

    /**
     * Re-arming an expired grant with the expiry it already carries changes
     * nothing.
     *
     * @return void
     */
    public function testRearmingWithTheSameExpiryChangesNothing(): void
    {
        [$table, $permission] = self::grants();

        $table->grant($permission->id, Carbon::parse('2026-07-01 11:00:00'));

        self::assertSame(GrantOutcome::UNCHANGED, $table->rearm($permission->id, Carbon::parse('2026-07-01 11:00:00'))?->outcome);
    }

    /**
     * A grant or re-arm of a row that is gone writes nothing, on every driver,
     * and leaves the transaction usable.
     *
     * @return void
     */
    public function testAGrantOfARowThatIsGoneWritesNothing(): void
    {
        [$table, $permission] = self::grants();

        DB::table('permissions')->where('id', $permission->id)->delete();

        self::assertNull($table->grant($permission->id, null));
        self::assertNull($table->rearm($permission->id, null));
        self::assertSame([], self::expiries());
    }

    /**
     * A held row a concurrent call removed between the ignored insert and its
     * read is stored afresh, with the new expiry.
     *
     * @return void
     */
    public function testAHeldRowRemovedBeforeItIsReadIsStoredAfresh(): void
    {
        [$table, $role] = self::roleGrant();

        $inserts = self::interleaveWrites('authorizable_roles', static function (): void {
            DB::table('authorizable_roles')->delete();
        }, static function (): void {});

        self::assertSame(GrantOutcome::GRANTED, $table->grant($role->id, Carbon::parse('2026-07-09 12:00:00'))?->outcome);
        self::assertCount(2, $inserts);
        self::assertSame(['2026-07-09 12:00:00'], DB::table('authorizable_roles')->pluck('expires_at')->all());
    }

    /**
     * A held row a concurrent call keeps removing, even once the write is tried
     * again, is not reported written.
     *
     * @return void
     */
    public function testARowThatKeepsBeingRemovedIsNotReported(): void
    {
        [$table, $role] = self::roleGrant();

        $row     = (array) DB::table('authorizable_roles')->sole();
        $inserts = self::interleaveWrites('authorizable_roles', static function (): void {
            DB::table('authorizable_roles')->delete();
        }, static function () use ($row): void {
            DB::table('authorizable_roles')->insert($row);
        }, 2, 1);

        self::assertNull($table->grant($role->id, Carbon::parse('2026-07-09 12:00:00')));
        self::assertCount(2, $inserts);
    }

    /**
     * A failure of the insert other than a constraint's, such as a value too
     * long, is thrown rather than taken for a held row.
     *
     * @return void
     */
    public function testAFailureOtherThanAConstraintIsThrown(): void
    {
        $role    = Role::query()->create(['name' => 'editor']);
        $failure = new QueryException('testing', 'insert', [], new \PDOException('String data, right truncated', 22001));

        DB::listen(static function (QueryExecuted $query) use ($failure): void {
            if (\str_starts_with(\strtolower($query->sql), 'insert')) {
                throw $failure;
            }
        });

        $this->expectExceptionObject($failure);

        GrantChanges::table(GrantTarget::ROLE, new Reference('user', '1'), null, GrantScope::platform())->grant($role->id, null);
    }

    /**
     * Return a role's permission writer and two permissions to grant.
     *
     * @return array{
     *     0: \SineMacula\Laravel\Authorization\Services\Support\RolePermissionTable,
     *     1: \SineMacula\Laravel\Authorization\Models\Permission,
     *     2: \SineMacula\Laravel\Authorization\Models\Permission,
     * }
     */
    private static function grants(): array
    {
        $role = Role::query()->create(['name' => 'editor']);

        return [
            new RolePermissionTable($role),
            Permission::query()->create(['name' => 'posts:edit']),
            Permission::query()->create(['name' => 'posts:read']),
        ];
    }

    /**
     * Return a grantee's platform-wide role writer and a role it holds forever.
     *
     * @return array{\SineMacula\Laravel\Authorization\Services\Support\GrantTable, \SineMacula\Laravel\Authorization\Models\Role}
     */
    private static function roleGrant(): array
    {
        $role  = Role::query()->create(['name' => 'editor']);
        $table = GrantChanges::table(GrantTarget::ROLE, new Reference('user', '1'), null, GrantScope::platform());

        $table->grant($role->id, null);

        return [$table, $role];
    }

    /**
     * Return the expiry of every role permission row, in the order they were
     * written.
     *
     * @return list<string|null>
     */
    private static function expiries(): array
    {
        /** @var list<string|null> */
        return DB::table('role_permissions')->pluck('expires_at')->all();
    }
}
