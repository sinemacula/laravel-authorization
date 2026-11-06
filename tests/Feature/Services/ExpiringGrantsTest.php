<?php

declare(strict_types = 1);

namespace Tests\Feature\Services;

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Enums\GrantOutcome;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\Support\ExpiringGrants;
use SineMacula\Laravel\Authorization\Services\Support\RolePermissionTable;
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

        self::assertSame(GrantOutcome::GRANTED, $change->outcome);
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

        self::assertSame(GrantOutcome::UNCHANGED, $same->outcome);
        self::assertSame('2026-07-02 12:00:00', $same->previousExpiresAt?->format('Y-m-d H:i:s'));
        self::assertSame(GrantOutcome::UNCHANGED, $forever->outcome);
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

        self::assertSame(GrantOutcome::EXPIRY_CHANGED, $later->outcome);
        self::assertSame('2026-07-02 12:00:00', $later->previousExpiresAt?->format('Y-m-d H:i:s'));
        self::assertSame(GrantOutcome::EXPIRY_CHANGED, $forever->outcome);
        self::assertSame(GrantOutcome::EXPIRY_CHANGED, $dated->outcome);
        self::assertNull($dated->previousExpiresAt);
        self::assertSame(['2026-07-04 12:00:00'], self::expiries());
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

        self::assertSame(GrantOutcome::REARMED, $change->outcome);
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

        self::assertSame(GrantOutcome::GRANTED, $table->rearm($missing->id, null)->outcome);
        self::assertSame(GrantOutcome::UNCHANGED, $table->rearm($permission->id, Carbon::parse('2026-07-09 12:00:00'))->outcome);
        self::assertSame(GrantOutcome::UNCHANGED, $table->rearm($other->id, Carbon::parse('2026-07-09 12:00:00'))->outcome);

        Carbon::setTestNow('2026-07-02 12:00:00');

        $rearmed = $table->rearm($permission->id, Carbon::parse('2026-07-09 12:00:00'));

        self::assertSame(GrantOutcome::REARMED, $rearmed->outcome);
        self::assertSame('2026-07-02 12:00:00', $rearmed->previousExpiresAt?->format('Y-m-d H:i:s'));
        self::assertSame('2026-07-09 12:00:00', DB::table('role_permissions')->where('permission_id', $permission->id)->value('expires_at'));
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

        self::assertSame(GrantOutcome::UNCHANGED, $table->rearm($permission->id, Carbon::parse('2026-07-01 11:00:00'))->outcome);
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
