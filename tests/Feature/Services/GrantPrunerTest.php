<?php

declare(strict_types = 1);

namespace Tests\Feature\Services;

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Events\Identity\PermissionExpired;
use SineMacula\Laravel\Authorization\Events\Identity\PolicyExpired;
use SineMacula\Laravel\Authorization\Events\Identity\RoleExpired;
use SineMacula\Laravel\Authorization\Events\Identity\RoleRevoked;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\GrantPruner;
use SineMacula\Laravel\Authorization\Services\PruneResult;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\ReadsDispatchedEvents;
use Tests\Feature\Stubs\NumberedIdentity;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for removing expired grants and the grants of grantees that no
 * longer exist.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GrantPruner::class)]
#[CoversClass(PruneResult::class)]
final class GrantPrunerTest extends TestCase
{
    use ReadsDispatchedEvents;

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
     * Expired grants of every kind are removed and reported, with no actor, the
     * scope and the expiry; live and permanent grants stay.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRemovesExpiredGrantsOfEveryKind(): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $role   = Role::create(['name' => 'editor']);
        $tenant = new Reference('stub_tenant', 'tenant-a');

        $user->assignRole($role, Carbon::parse('2026-07-01 11:00:00'), $tenant);
        $user->assignRole(Role::create(['name' => 'viewer']));
        $user->givePermission(Permission::create(['name' => 'posts:edit']), Carbon::parse('2026-07-01 11:30:00'));
        $user->givePermission(Permission::create(['name' => 'posts:read']), Carbon::parse('2026-07-01 13:00:00'));
        $user->attachPolicy(Policy::create(['name' => 'readers', 'document' => ['version' => 1, 'statements' => []]]), Carbon::parse('2026-07-01 12:00:00'));

        Event::fake();

        $result = self::pruner()->prune();

        self::assertSame(3, $result->expired);
        self::assertSame(0, $result->orphaned);
        self::assertSame(['viewer'], Role::query()->whereKey(DB::table('authorizable_roles')->pluck('role_id'))->pluck('name')->all());
        self::assertSame(1, DB::table('authorizable_permissions')->count());
        self::assertSame(0, DB::table('authorizable_policies')->count());

        $expired = self::dispatchedEvents(RoleExpired::class);

        self::assertCount(1, $expired);
        self::assertNull($expired[0]->operation->actor);
        self::assertSame('editor', $expired[0]->name);
        self::assertEquals($tenant, $expired[0]->scope->tenant);
        self::assertSame('2026-07-01 11:00:00', $expired[0]->expiredAt->format('Y-m-d H:i:s'));
        self::assertSame('UTC', $expired[0]->expiredAt->getTimezone()->getName());
        Event::assertDispatchedTimes(PermissionExpired::class, 1);
        Event::assertDispatchedTimes(PolicyExpired::class, 1);
    }

    /**
     * Expired grants are removed a chunk at a time until none is left, each
     * chunk one operation.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRemovesExpiredGrantsInChunks(): void
    {
        for ($i = 0; $i < 5; $i++) {
            StubIdentity::create(['id' => "user-{$i}"])->assignRole(Role::create(['name' => "role-{$i}"]), Carbon::parse('2026-07-01 11:00:00'));
        }

        Event::fake();

        self::assertSame(5, self::pruner()->prune(2)->expired);
        self::assertSame(0, DB::table('authorizable_roles')->count());

        $operations = \array_unique(\array_map(static fn (RoleExpired $event): string => $event->operation->id, self::dispatchedEvents(RoleExpired::class)));

        self::assertCount(3, $operations);
    }

    /**
     * Pretending counts what would be removed and removes nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testPretendingCountsWithoutRemoving(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);
        $gone = StubIdentity::create(['id' => 'user-2']);

        $user->assignRole(Role::create(['name' => 'editor']), Carbon::parse('2026-07-01 11:00:00'));
        $gone->assignRole(Role::create(['name' => 'viewer']));
        $gone->givePermission(Permission::create(['name' => 'posts:read']));

        DB::table('stub_identities')->where('id', 'user-2')->delete();

        Event::fake();

        $result = self::pruner()->prune(1000, true);

        self::assertSame(1, $result->expired);
        self::assertSame(2, $result->orphaned);
        self::assertSame(2, DB::table('authorizable_roles')->count());
        self::assertSame(1, DB::table('authorizable_permissions')->count());
        Event::assertNothingDispatched();
    }

    /**
     * The grants of a grantee that no longer exists are revoked and reported; a
     * soft-deleted grantee keeps its grants, and a grantee type naming no model
     * class is reported and left.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRevokesTheGrantsOfGranteesThatAreGone(): void
    {
        $role  = Role::create(['name' => 'editor']);
        $gone  = StubIdentity::create(['id' => 'user-gone']);
        $kept  = StubIdentity::create(['id' => 'user-kept']);
        $soft  = NumberedIdentity::create(['name' => 'Ada']);
        $other = NumberedIdentity::create(['name' => 'Grace']);

        $gone->assignRole($role);
        $kept->assignRole($role);
        $soft->assignRole($role);
        $other->assignRole($role);

        DB::table('stub_identities')->where('id', 'user-gone')->delete();
        DB::table('stub_numbered_identities')->where('id', $other->id)->delete();
        $soft->delete();

        DB::table('authorizable_roles')->insert(['role_id' => $role->id, 'authorizable_type' => 'unmapped_type', 'authorizable_id' => '1']);

        Event::fake();

        $result = self::pruner()->prune();

        self::assertSame(2, $result->orphaned);
        self::assertSame(['unmapped_type'], $result->unresolvedTypes);
        self::assertEqualsCanonicalizing(['user-kept', (string) $soft->id, '1'], DB::table('authorizable_roles')->pluck('authorizable_id')->all());
        Event::assertDispatchedTimes(RoleRevoked::class, 2);
        Event::assertDispatched(RoleRevoked::class, static fn (RoleRevoked $event): bool => $event->grantee->id === 'user-gone' && $event->operation->actor === null);
    }

    /**
     * Return the grant pruner the container builds.
     *
     * @return \SineMacula\Laravel\Authorization\Services\GrantPruner
     */
    private static function pruner(): GrantPruner
    {
        return app(GrantPruner::class);
    }
}
