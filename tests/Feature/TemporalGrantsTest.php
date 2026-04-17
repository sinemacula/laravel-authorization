<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Registrars\BladeDirectiveRegistrar;
use SineMacula\Laravel\Authorization\Registrars\EventListenerRegistrar;
use SineMacula\Laravel\Authorization\Registrars\GateRegistrar;
use SineMacula\Laravel\Authorization\Traits\HasPermissions;
use SineMacula\Laravel\Authorization\Traits\HasPolicies;
use SineMacula\Laravel\Authorization\Traits\HasRoles;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature coverage for temporal grants (issue #30).
 *
 * Each `authorizable_*` pivot carries a nullable `expires_at`
 * column. Null means "forever"; a concrete timestamp bounds the
 * grant and is filtered out of the relation the moment the clock
 * passes it, without requiring a sweeper run. Admin-time APIs
 * accept the optional `$expiresAt` parameter on
 * `assignRole()` / `givePermission()` / `attachPolicy()`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthorizationServiceProvider::class)]
#[CoversClass(GateRegistrar::class)]
#[CoversClass(BladeDirectiveRegistrar::class)]
#[CoversClass(EventListenerRegistrar::class)]
#[CoversClass(ResolutionCache::class)]
#[CoversTrait(HasRoles::class)]
#[CoversTrait(HasPermissions::class)]
#[CoversTrait(HasPolicies::class)]
final class TemporalGrantsTest extends TestCase
{
    /**
     * Reset the Carbon test now between tests so wall-clock
     * travel never leaks across scenarios.
     *
     * @return void
     */
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * A role assigned with a future `expiresAt` is present on
     * the relation until the clock passes the expiry.
     *
     * @return void
     */
    public function testFutureExpiryIsPresentThenFiltered(): void
    {
        Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'oncall',
            'guard_name' => 'web',
        ]);

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);

        Carbon::setTestNow('2026-01-01 12:00:00');
        $user->assignRole('oncall', expiresAt: Carbon::parse('2026-01-01 13:00:00'));

        self::assertTrue($user->fresh()?->hasRole('oncall'));

        $this->advanceClockTo('2026-01-01 13:30:00', $user);
        self::assertFalse($user->fresh()?->hasRole('oncall'));
    }

    /**
     * A permission with a future expiry resolves under
     * `hasPermission()` until the clock passes the expiry.
     *
     * @return void
     */
    public function testPermissionExpiryIsFilteredFromRelation(): void
    {
        Permission::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'emergency:publish',
            'guard_name' => 'web',
        ]);

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);

        Carbon::setTestNow('2026-02-01 10:00:00');
        $user->givePermission('emergency:publish', expiresAt: Carbon::parse('2026-02-01 10:30:00'));

        self::assertTrue($user->fresh()?->hasPermission('emergency:publish'));

        $this->advanceClockTo('2026-02-01 11:00:00', $user);
        self::assertFalse($user->fresh()?->hasPermission('emergency:publish'));
    }

    /**
     * A policy attached with a future expiry is returned by
     * `getPolicies()` until the clock passes the expiry, then
     * disappears.
     *
     * @return void
     */
    public function testPolicyExpiryIsFilteredFromRelation(): void
    {
        $policy = Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'break-glass',
            'document' => [
                'statements' => [['effect' => 'allow', 'actions' => ['systems:override']]],
            ],
        ]);

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);

        Carbon::setTestNow('2026-03-01 09:00:00');
        $user->attachPolicy($policy, expiresAt: Carbon::parse('2026-03-01 09:15:00'));

        self::assertCount(1, $user->fresh()?->getPolicies() ?? []);

        $this->advanceClockTo('2026-03-01 10:00:00', $user);
        self::assertCount(0, $user->fresh()?->getPolicies() ?? []);
    }

    /**
     * Passing no `expiresAt` (the default) creates a forever
     * grant — no `expires_at` is persisted on the pivot.
     *
     * @return void
     */
    public function testForeverGrantIsTheDefaultBehaviour(): void
    {
        Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'staff',
            'guard_name' => 'web',
        ]);

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $user->assignRole('staff');

        $row = DB::table('authorizable_roles')
            ->where('authorizable_type', $user->getMorphClass())
            ->where('authorizable_id', (string) $user->getKey())
            ->first();

        self::assertNotNull($row);
        self::assertNull($row->expires_at);
    }

    /**
     * `pivot->expires_at` is cast to a Carbon instance so
     * consumers can render remaining lifetime without parsing
     * the string themselves — `withCasts()` on each relation
     * backs up the claim in the relation docblock (issue #78).
     *
     * @return void
     */
    public function testPivotExpiresAtIsCastToCarbon(): void
    {
        Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'oncall',
            'guard_name' => 'web',
        ]);

        $user    = StubIdentity::create(['id' => (string) Str::uuid()]);
        $expires = Carbon::parse('2026-06-01 09:00:00');

        Carbon::setTestNow('2026-06-01 08:00:00');
        $user->assignRole('oncall', expiresAt: $expires);

        $role = $user->fresh()?->roles()->first();

        self::assertNotNull($role);
        self::assertInstanceOf(Carbon::class, $role->pivot->expires_at);
        self::assertTrue($expires->equalTo($role->pivot->expires_at));
    }

    /**
     * A past-dated grant is invisible on the relation the moment
     * it is persisted — the filter evaluates against the current
     * time on every read, not just at load time.
     *
     * @return void
     */
    public function testPastDatedGrantIsImmediatelyInvisible(): void
    {
        Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'shadowed',
            'guard_name' => 'web',
        ]);

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);

        Carbon::setTestNow('2026-04-01 12:00:00');
        $user->assignRole('shadowed', expiresAt: Carbon::parse('2026-04-01 11:00:00'));

        self::assertFalse($user->fresh()?->hasRole('shadowed'));
    }

    /**
     * A temporal grant and a forever grant to the same identity
     * coexist on separate pivots — the forever grant stays even
     * after the temporal one expires.
     *
     * @return void
     */
    public function testForeverAndTemporalGrantsCoexist(): void
    {
        Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'staff',
            'guard_name' => 'web',
        ]);
        Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'oncall',
            'guard_name' => 'web',
        ]);

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);

        Carbon::setTestNow('2026-05-01 08:00:00');
        $user->assignRole('staff');
        $user->assignRole('oncall', expiresAt: Carbon::parse('2026-05-01 09:00:00'));

        self::assertSame(
            ['oncall', 'staff'],
            $this->sortedRoleNames($user->fresh()),
        );

        $this->advanceClockTo('2026-05-01 10:00:00', $user);
        self::assertSame(
            ['staff'],
            $this->sortedRoleNames($user->fresh()),
        );
    }

    /**
     * A cached `getRoles()` snapshot bounded by a temporal grant's
     * `expires_at` invalidates itself once the clock passes the
     * expiry — no manual `forget()` call required. Regression
     * coverage for ISSUES.md #77: the cache writes the entry
     * with `min(configured-ttl, seconds-until-nearest-expiry) -
     * 1s` so wall-clock advance alone is enough to drop the
     * stored row.
     *
     * @return void
     */
    public function testCachedRolesExpireWithTemporalGrantWithoutManualForget(): void
    {
        // Wire a persistent array-backed cache so the entry
        // survives a memo reset and the TTL bound is the only
        // thing governing visibility.
        /** @var \Illuminate\Contracts\Config\Repository $config */
        $config = $this->app->make('config');
        $config->set('authorization.cache.store', 'array');
        $config->set('authorization.cache.ttl', 3600);
        $config->set('authorization.cache.prefix', 'authorization-temporal');

        $this->app->forgetInstance(ResolutionCache::class);
        (new AuthorizationServiceProvider($this->app))->register();

        Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'oncall',
            'guard_name' => 'web',
        ]);

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);

        Carbon::setTestNow('2026-07-01 12:00:00');
        $user->assignRole('oncall', expiresAt: Carbon::parse('2026-07-01 12:05:00'));

        // Prime the persistent entry at t=12:00, bounded to
        // ~299s (5 minutes minus the shave).
        self::assertSame(['oncall'], $user->fresh()?->getRoles());

        // Walk past the expiry — the TTL bound means the stored
        // entry has elapsed even though no mutation event fired.
        Carbon::setTestNow('2026-07-01 12:10:00');

        // A fresh principal instance drops the in-memory memo so
        // the persistent tier is the sole source — its entry is
        // now expired and the resolver observes the DB-filtered
        // empty set.
        $fresh = $user->fresh();
        self::assertNotNull($fresh);

        // Wipe the singleton's in-memory memo that was primed at
        // t=12:00 — the persistent tier is the one under test.
        $this->app->forgetInstance(ResolutionCache::class);
        (new AuthorizationServiceProvider($this->app))->register();

        self::assertSame([], $fresh->getRoles());
    }

    /**
     * Advance the clock and invalidate the resolution cache for
     * the supplied principal in the same step.
     *
     * Temporal grants are filtered at the DB layer on every
     * relation read, but the `ResolutionCache` has no way to
     * observe wall-clock advance — when present it memoises the
     * role / permission list per principal and keeps returning
     * the cached set until an invalidation event fires. Tests
     * that walk the clock forward must drop the memoised entry
     * manually so the next read observes the expiry.
     *
     * @param  string  $instant
     * @param  object  $principal
     * @return void
     */
    private function advanceClockTo(string $instant, object $principal): void
    {
        Carbon::setTestNow(Carbon::parse($instant));

        if ($this->app->bound(ResolutionCache::class)) {
            $this->app->make(ResolutionCache::class)->forget($principal);
        }
    }

    /**
     * Sort an identity's role names for stable comparison.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity|null  $user
     * @return array<int, string>
     */
    private function sortedRoleNames(?StubIdentity $user): array
    {
        $names = $user?->getRoles() ?? [];
        \sort($names);

        return \array_values($names);
    }
}
