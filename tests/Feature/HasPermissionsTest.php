<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authorization\Concerns\HasPermissions;
use SineMacula\Laravel\Authorization\Events\Identity\PermissionExpiryChanged;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use Tests\Concerns\ChecksGrantExpiry;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for `HasPermissions::getPermissions()` on one identity instance
 * reused across a cached entry's lifetime.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversTrait(HasPermissions::class)]
final class HasPermissionsTest extends TestCase
{
    use ChecksGrantExpiry;

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
     * A direct grant records when it was made and when it last changed.
     *
     * @return void
     */
    public function testGrantKeepsItsTimestamps(): void
    {
        Carbon::setTestNow('2026-07-01 12:00:00');

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $user->givePermission(Permission::create(['name' => 'posts:edit', 'guard' => 'web']));

        Carbon::setTestNow('2026-07-01 12:30:00');

        $user->givePermission('posts:edit', Carbon::parse('2026-07-01 14:00:00'));

        $row = DB::table('authorizable_permissions')->sole();

        self::assertSame('2026-07-01 12:00:00', Carbon::parse((string) $row->created_at)->format('Y-m-d H:i:s'));
        self::assertSame('2026-07-01 12:30:00', Carbon::parse((string) $row->updated_at)->format('Y-m-d H:i:s'));
    }

    /**
     * A permission granted directly until 12:05 lapses at 12:05 for the same
     * identity instance.
     *
     * @return void
     */
    public function testExpiringDirectPermissionLapsesForTheSameInstance(): void
    {
        $user = $this->identity();
        $user->givePermission(Permission::create(['name' => 'posts:publish', 'guard' => 'web']), Carbon::parse('2026-07-01 12:05:00'));

        self::assertSame(['posts:publish'], $user->getPermissions());

        Carbon::setTestNow('2026-07-01 12:05:00');

        self::assertSame([], $user->getPermissions());
    }

    /**
     * A permission held through a role assigned until 12:05 lapses at 12:05 for
     * the same identity instance, which reloads its roles too.
     *
     * @return void
     */
    public function testPermissionThroughExpiringRoleLapsesForTheSameInstance(): void
    {
        $role = Role::create(['name' => 'publisher', 'guard' => 'web']);
        $role->givePermission(Permission::create(['name' => 'posts:publish', 'guard' => 'web']));

        $user = $this->identity();
        $user->assignRole($role, Carbon::parse('2026-07-01 12:05:00'));

        self::assertSame(['posts:publish'], $user->getPermissions());

        Carbon::setTestNow('2026-07-01 12:05:00');

        self::assertSame([], $user->getPermissions());
    }

    /**
     * A live entry is served without reading the permissions or roles again.
     *
     * @return void
     */
    public function testLiveEntryDoesNotReloadThePermissions(): void
    {
        $user = $this->identity();
        $user->givePermission(Permission::create(['name' => 'posts:publish', 'guard' => 'web']), Carbon::parse('2026-07-01 13:00:00'));

        self::assertSame(['posts:publish'], $user->getPermissions());

        DB::flushQueryLog();
        DB::enableQueryLog();

        Carbon::setTestNow('2026-07-01 12:30:00');

        self::assertSame(['posts:publish'], $user->getPermissions());
        self::assertSame([], DB::getQueryLog());

        DB::disableQueryLog();
    }

    /**
     * Return the grant table the expiry check reads.
     *
     * @return string
     */
    #[\Override]
    protected static function grantTable(): string
    {
        return 'authorizable_permissions';
    }

    /**
     * Return the event a change of the grant's expiry dispatches.
     *
     * @return class-string
     */
    #[\Override]
    protected static function expiryChangedEvent(): string
    {
        return PermissionExpiryChanged::class;
    }

    /**
     * Return the name of the row the expiry check grants.
     *
     * @return string
     */
    #[\Override]
    protected static function grantedName(): string
    {
        return 'posts:edit';
    }

    /**
     * Grant the identity the checked row until the given instant.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $identity
     * @param  \DateTimeInterface  $expiresAt
     * @return void
     */
    #[\Override]
    protected function grantUntil(StubIdentity $identity, \DateTimeInterface $expiresAt): void
    {
        $identity->givePermission(Permission::query()->firstOrCreate(['name' => 'posts:edit']), $expiresAt);
    }

    /**
     * Return the names of the rows the identity holds.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $identity
     * @return list<string>
     */
    #[\Override]
    protected function heldNames(StubIdentity $identity): array
    {
        /** @var list<string> */
        return $identity->permissions->pluck('name')->all();
    }

    /**
     * Create an identity at 12:00.
     *
     * @return \Tests\Feature\Stubs\StubIdentity
     */
    private function identity(): StubIdentity
    {
        Carbon::setTestNow('2026-07-01 12:00:00');

        return StubIdentity::create(['id' => (string) Str::uuid()]);
    }
}
