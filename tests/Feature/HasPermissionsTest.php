<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authorization\Concerns\HasPermissions;
use SineMacula\Laravel\Authorization\Events\Identity\PermissionExpiryChanged;
use SineMacula\Laravel\Authorization\Events\Identity\PermissionGranted;
use SineMacula\Laravel\Authorization\Events\Identity\PermissionRevoked;
use SineMacula\Laravel\Authorization\Exceptions\UnknownPermissionException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\ChecksGrantExpiry;
use Tests\Concerns\ChecksGrantsByName;
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
    use ChecksGrantExpiry, ChecksGrantsByName;

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
     * A grant in a tenant through the trait can be limited to that tenant, and
     * reaches the tenants below it by default.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPermissionInATenantCanBeLimitedToIt(): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $tenant = new Reference('stub_tenant', 'tenant-a');

        Permission::create(['name' => 'posts:edit']);

        $user->givePermission('posts:edit', null, $tenant, false);

        Permission::create(['name' => 'posts:read']);
        $user->givePermission('posts:read', null, $tenant);

        $reaches = DB::table('authorizable_permissions')->pluck('include_subtree')->map(static fn (mixed $reach): bool => (bool) $reach)->all();

        self::assertEqualsCanonicalizing([false, true], $reaches);
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
     * The direct permissions relation can be queried from outside the identity,
     * and its pivot carries each grant's expiry.
     *
     * @return void
     */
    public function testPermissionsRelationIsQueryable(): void
    {
        Carbon::setTestNow('2026-07-01 12:00:00');

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $user->givePermission(Permission::create(['name' => 'posts:edit', 'guard' => 'web']), Carbon::parse('2026-07-01 13:00:00'));

        $permission = $user->permissions()->sole();

        self::assertSame('posts:edit', $permission->name);
        self::assertSame('2026-07-01 13:00:00', Carbon::parse((string) $permission->pivot->expires_at)->format('Y-m-d H:i:s')); // @phpstan-ignore property.notFound
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

        Carbon::setTestNow('2026-07-01 12:04:00');

        self::assertSame(['posts:publish'], $user->getPermissions());
        self::assertSame([], DB::getQueryLog());

        DB::disableQueryLog();
    }

    /**
     * The write methods go through the grant service: a grant of what is held
     * dispatches nothing, and each returns the identity.
     *
     * @return void
     */
    public function testWritesGoThroughTheGrantService(): void
    {
        Carbon::setTestNow('2026-07-01 12:00:00');
        Event::fake([PermissionGranted::class, PermissionRevoked::class]);

        $user       = StubIdentity::create(['id' => (string) Str::uuid()]);
        $permission = Permission::query()->create(['name' => 'posts:edit']);
        $expires    = Carbon::parse('2026-07-02 12:00:00', 'UTC');

        self::assertSame($user, $user->givePermission($permission, $expires));
        self::assertSame($user, $user->givePermission('posts:edit', $expires));
        self::assertSame('2026-07-02 12:00:00', DB::table('authorizable_permissions')->value('expires_at'));
        self::assertSame($user, $user->syncPermissions([$permission]));
        Event::assertDispatchedTimes(PermissionGranted::class, 1);

        self::assertSame($user, $user->revokePermission($permission));
        self::assertSame($user, $user->revokePermissionTo('posts:edit'));
        self::assertSame(0, DB::table('authorizable_permissions')->count());
        Event::assertDispatchedTimes(PermissionRevoked::class, 1);
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
     * Return the column of the grant table that names the granted row.
     *
     * @return string
     */
    #[\Override]
    protected static function targetColumn(): string
    {
        return 'permission_id';
    }

    /**
     * Return the exception a name no row answers raises.
     *
     * @return class-string<\Throwable>
     */
    #[\Override]
    protected static function unknownNameException(): string
    {
        return UnknownPermissionException::class;
    }

    /**
     * Return the event a revocation dispatches.
     *
     * @return class-string
     */
    #[\Override]
    protected static function revokedEvent(): string
    {
        return PermissionRevoked::class;
    }

    /**
     * Create a permission with the given name and owner, for the `web` guard.
     *
     * @param  string  $name
     * @param  array{tenant_type: string|null, tenant_id: string|null}  $owner
     * @return \Illuminate\Database\Eloquent\Model
     */
    #[\Override]
    protected static function createNamed(string $name, array $owner): Model
    {
        return Permission::query()->create(['name' => $name, 'guard' => 'web'] + $owner);
    }

    /**
     * Grant the permission to the identity.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $identity
     * @param  \Illuminate\Database\Eloquent\Model  $row
     * @param  \DateTimeInterface|null  $expiresAt
     * @param  \Illuminate\Database\Eloquent\Model|null  $tenant
     * @return void
     */
    #[\Override]
    protected function grantTo(StubIdentity $identity, Model $row, ?\DateTimeInterface $expiresAt = null, ?Model $tenant = null): void
    {
        \assert($row instanceof Permission);

        $identity->givePermission($row, $expiresAt, $tenant);
    }

    /**
     * Revoke the permission, or the permission name, from the identity.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $identity
     * @param  \Illuminate\Database\Eloquent\Model|string  $grant
     * @return void
     */
    #[\Override]
    protected function revokeFrom(StubIdentity $identity, Model|string $grant): void
    {
        \assert(\is_string($grant) || $grant instanceof Permission);

        $identity->revokePermission($grant);
    }

    /**
     * Synchronise the identity's permissions to the given ones and names.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $identity
     * @param  list<\Illuminate\Database\Eloquent\Model|string>  $grants
     * @return void
     */
    #[\Override]
    protected function syncTo(StubIdentity $identity, array $grants): void
    {
        $typed = [];

        foreach ($grants as $grant) {
            \assert(\is_string($grant) || $grant instanceof Permission);

            $typed[] = $grant;
        }

        $identity->syncPermissions($typed);
    }

    /**
     * Return the permission a revocation event reports.
     *
     * @param  object  $event
     * @return \SineMacula\Laravel\Authorization\Support\Reference|null
     */
    #[\Override]
    protected static function revokedRow(object $event): ?Reference
    {
        return $event instanceof PermissionRevoked ? $event->permission : null;
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
