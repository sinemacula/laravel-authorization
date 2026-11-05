<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authorization\Concerns\HasRoles;
use SineMacula\Laravel\Authorization\Events\Identity\RoleExpiryChanged;
use SineMacula\Laravel\Authorization\Events\Identity\RoleRevoked;
use SineMacula\Laravel\Authorization\Exceptions\UnknownRoleException;
use SineMacula\Laravel\Authorization\Models\Role;
use Tests\Concerns\ChecksGrantExpiry;
use Tests\Concerns\ChecksGrantsByName;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for `HasRoles::getRoles()` on one identity instance reused
 * across a cached entry's lifetime.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversTrait(HasRoles::class)]
final class HasRolesTest extends TestCase
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
     * A role assigned until 12:05 lapses at 12:05 for the same identity
     * instance, which reloads its roles once the cached entry has lapsed.
     *
     * @return void
     */
    public function testExpiringRoleLapsesForTheSameInstance(): void
    {
        $user = $this->identityWithRoleUntil('2026-07-01 12:05:00');

        self::assertSame(['on-call'], $user->getRoles());

        Carbon::setTestNow('2026-07-01 12:05:00');

        self::assertSame([], $user->getRoles());
    }

    /**
     * A live entry is served without reading the roles again.
     *
     * @return void
     */
    public function testLiveEntryDoesNotReloadTheRoles(): void
    {
        $user = $this->identityWithRoleUntil('2026-07-01 13:00:00');

        self::assertSame(['on-call'], $user->getRoles());

        DB::flushQueryLog();
        DB::enableQueryLog();

        Carbon::setTestNow('2026-07-01 12:30:00');

        self::assertSame(['on-call'], $user->getRoles());
        self::assertSame([], DB::getQueryLog());

        DB::disableQueryLog();
    }

    /**
     * An assignment records when it was made and when it last changed.
     *
     * @return void
     */
    public function testAssignmentKeepsItsTimestamps(): void
    {
        $user = $this->identityWithRoleUntil('2026-07-01 13:00:00');

        Carbon::setTestNow('2026-07-01 12:30:00');

        $user->assignRole('on-call', Carbon::parse('2026-07-01 14:00:00'));

        $row = DB::table('authorizable_roles')->sole();

        self::assertSame('2026-07-01 12:00:00', Carbon::parse((string) $row->created_at)->format('Y-m-d H:i:s'));
        self::assertSame('2026-07-01 12:30:00', Carbon::parse((string) $row->updated_at)->format('Y-m-d H:i:s'));
    }

    /**
     * A role model matches only that row: a tenant's role that shares the name
     * and guard of a platform role does not pass a check for the platform's,
     * while a check by name is met by either.
     *
     * @return void
     */
    public function testHasRoleWithAModelMatchesOnlyThatRow(): void
    {
        $tenant   = self::createTenant('tenant-a');
        $platform = Role::create(['name' => 'manager', 'guard' => 'web']);
        $owned    = Role::create(['name' => 'manager', 'guard' => 'web'] + self::ownedBy($tenant));
        $user     = StubIdentity::create(['id' => (string) Str::uuid()]);

        $this->actAsTenant($tenant);

        $user->assignRole($owned);

        self::assertFalse($user->hasRole($platform));
        self::assertTrue($user->hasRole($owned));
        self::assertTrue($user->hasRole('manager'));
        self::assertFalse($user->hasRole('director'));
    }

    /**
     * Return the grant table the expiry check reads.
     *
     * @return string
     */
    #[\Override]
    protected static function grantTable(): string
    {
        return 'authorizable_roles';
    }

    /**
     * Return the event a change of the grant's expiry dispatches.
     *
     * @return class-string
     */
    #[\Override]
    protected static function expiryChangedEvent(): string
    {
        return RoleExpiryChanged::class;
    }

    /**
     * Return the name of the row the expiry check grants.
     *
     * @return string
     */
    #[\Override]
    protected static function grantedName(): string
    {
        return 'on-call';
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
        $identity->assignRole(Role::query()->firstOrCreate(['name' => 'on-call']), $expiresAt);
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
        return $identity->roles->pluck('name')->all();
    }

    /**
     * Return the column of the grant table that names the granted row.
     *
     * @return string
     */
    #[\Override]
    protected static function targetColumn(): string
    {
        return 'role_id';
    }

    /**
     * Return the exception a name no row answers raises.
     *
     * @return class-string<\Throwable>
     */
    #[\Override]
    protected static function unknownNameException(): string
    {
        return UnknownRoleException::class;
    }

    /**
     * Return the event a revocation dispatches.
     *
     * @return class-string
     */
    #[\Override]
    protected static function revokedEvent(): string
    {
        return RoleRevoked::class;
    }

    /**
     * Create a role with the given name and owner, for the `web` guard.
     *
     * @param  string  $name
     * @param  array{tenant_type: string|null, tenant_id: string|null}  $owner
     * @return \Illuminate\Database\Eloquent\Model
     */
    #[\Override]
    protected static function createNamed(string $name, array $owner): Model
    {
        return Role::query()->create(['name' => $name, 'guard' => 'web'] + $owner);
    }

    /**
     * Grant the role to the identity.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $identity
     * @param  \Illuminate\Database\Eloquent\Model  $row
     * @param  \DateTimeInterface|null  $expiresAt
     * @return void
     */
    #[\Override]
    protected function grantTo(StubIdentity $identity, Model $row, ?\DateTimeInterface $expiresAt = null): void
    {
        \assert($row instanceof Role);

        $identity->assignRole($row, $expiresAt);
    }

    /**
     * Revoke the role, or the role name, from the identity.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $identity
     * @param  \Illuminate\Database\Eloquent\Model|string  $grant
     * @return void
     */
    #[\Override]
    protected function revokeFrom(StubIdentity $identity, Model|string $grant): void
    {
        \assert(\is_string($grant) || $grant instanceof Role);

        $identity->revokeRole($grant);
    }

    /**
     * Synchronise the identity's roles to the given roles and names.
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
            \assert(\is_string($grant) || $grant instanceof Role);

            $typed[] = $grant;
        }

        $identity->syncRoles($typed);
    }

    /**
     * Return the role a revocation event reports.
     *
     * @param  object  $event
     * @return \Illuminate\Database\Eloquent\Model|null
     */
    #[\Override]
    protected static function revokedRow(object $event): ?Model
    {
        return $event instanceof RoleRevoked ? $event->role : null;
    }

    /**
     * Create an identity, at 12:00, holding a role until the given instant.
     *
     * @param  string  $expiresAt
     * @return \Tests\Feature\Stubs\StubIdentity
     */
    private function identityWithRoleUntil(string $expiresAt): StubIdentity
    {
        Carbon::setTestNow('2026-07-01 12:00:00');

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $user->assignRole(Role::create(['name' => 'on-call', 'guard' => 'web']), Carbon::parse($expiresAt));

        return $user;
    }
}
