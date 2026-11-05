<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Listeners\InvalidateResolutionCache;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Services\RoleService;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for `InvalidateResolutionCache`, which drops cached lookups
 * once the change they depend on has committed, keyed by the references the
 * events carry.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(InvalidateResolutionCache::class)]
final class InvalidateResolutionCacheTest extends TestCase
{
    /**
     * Bind an in-memory resolution cache, so the listener's invalidation is the
     * only path that clears an entry.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(ResolutionCache::class, new ResolutionCache(store: null));
    }

    /**
     * A grant drops the grantee's cached lookups once it commits, keyed by the
     * grantee reference the event carries, and not before.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGrantDropsTheGranteesEntriesOnceItCommits(): void
    {
        $user = StubIdentity::query()->create(['id' => 'user-1']);
        $role = Role::query()->create(['name' => 'editor']);

        self::prime($user);

        DB::transaction(static function () use ($user, $role): void {
            app(GrantService::class)->grantRole(new Reference($user->getMorphClass(), 'user-1'), $role);

            self::assertSame(['stale'], self::cached($user));
        });

        self::assertSame(['live'], self::cached($user));
    }

    /**
     * A grant that rolls back with its enclosing transaction leaves the cache
     * as it was.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARolledBackGrantInvalidatesNothing(): void
    {
        $user = StubIdentity::query()->create(['id' => 'user-1']);
        $role = Role::query()->create(['name' => 'editor']);

        self::prime($user);

        try {
            DB::transaction(static function () use ($user, $role): never {
                app(GrantService::class)->grantRole($user, $role);

                throw new \RuntimeException('Rolled back.');
            });
        } catch (\RuntimeException) {
            // The enclosing transaction rolled back.
        }

        self::assertSame(['stale'], self::cached($user));
    }

    /**
     * A permission granted to a role flushes the cached lookups once it
     * commits.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARolePermissionGrantFlushesTheCache(): void
    {
        $user       = StubIdentity::query()->create(['id' => 'user-1']);
        $role       = Role::query()->create(['name' => 'editor']);
        $permission = Permission::query()->create(['name' => 'posts:edit']);

        self::prime($user);

        app(RoleService::class)->grantPermission($role, $permission);

        self::assertSame(['live'], self::cached($user));
    }

    /**
     * Prime the grantee's cached permissions with a stale answer.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $user
     * @return void
     */
    private static function prime(StubIdentity $user): void
    {
        app(ResolutionCache::class)->rememberPermissions($user, static fn (): array => ['stale']);
    }

    /**
     * Return the grantee's cached permissions, resolving a live answer when
     * nothing is cached.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $user
     * @return list<string>
     */
    private static function cached(StubIdentity $user): array
    {
        /** @var list<string> */
        return app(ResolutionCache::class)->rememberPermissions($user, static fn (): array => ['live']);
    }
}
