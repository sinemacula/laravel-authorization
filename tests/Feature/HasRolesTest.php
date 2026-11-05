<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authorization\Concerns\HasRoles;
use SineMacula\Laravel\Authorization\Models\Role;
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
