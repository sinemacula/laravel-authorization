<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Contracts\PolicyResolver;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Performance budget for RBAC lookup N+1 safety.
 *
 * Within a single request the authorization pipeline must resolve roles,
 * permissions, and policies at most once per principal. Subsequent `can()`
 * invocations on the same principal are expected to hit the memoisation tier of
 * `ResolutionCache` and emit zero additional database queries — regression
 * coverage for §12.2 of the spec.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(AuthorizationManager::class)]
#[CoversClass(ResolutionCache::class)]
final class RbacQueryBudgetTest extends TestCase
{
    /** @var list<string> Permission fixture reused across every assertion. */
    private const array PERMISSION_NAMES = [
        'posts:create',
        'posts:read',
        'posts:update',
        'posts:delete',
        'posts:publish',
    ];

    /**
     * Wire the resolution cache to the array store so both the memoisation and
     * persistent tiers are live — the persistent tier is the only layer that
     * can survive a scoped clone of the manager, so a full N+1 assertion must
     * exercise both.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $app = $this->app;
        self::assertNotNull($app, 'Testbench application must be booted by setUp().');

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(ConfigRepository::class);
        $config->set('authorization.cache.store', 'array');
        $config->set('authorization.cache.ttl', 0);
        $config->set('authorization.cache.prefix', 'authorization-rbac-budget');

        $app->forgetInstance(ResolutionCache::class);
        $app->forgetInstance(PolicyResolver::class);

        (new AuthorizationServiceProvider($app))->register();
    }

    /**
     * A user carrying a role with five permissions must not emit a database
     * query on any `can()` beyond the first. The initial resolution loads
     * roles, role permissions, direct permissions, and attached policies —
     * every subsequent `can()` for the same principal during the same request
     * is served from cache.
     *
     * @return void
     */
    public function testRepeatedCanEmitsNoAdditionalQueriesAfterFirstResolution(): void
    {
        $user = $this->makeEditorWithFivePermissions();

        $app = $this->app;
        self::assertNotNull($app, 'Testbench application must be booted by setUp().');

        /** @var \SineMacula\Laravel\Authorization\AuthorizationManager $manager */
        $manager = $app->make(AuthorizationManager::class);

        // Prime the cache — the first `can()` pays the full
        // resolution cost. Budget: at most six queries (roles,
        // role-permissions, direct permissions, attached policies,
        // plus up to two guard/tenant lookups executed inside the
        // trait helpers). This is loose on purpose — the hard
        // assertion below is the zero-query floor on subsequent
        // calls.
        DB::enableQueryLog();
        DB::flushQueryLog();

        $manager->for($user)->can(self::PERMISSION_NAMES[0]);

        $primingQueries = DB::getQueryLog();
        self::assertLessThanOrEqual(
            6,
            \count($primingQueries),
            'Initial RBAC resolution exceeded the 6-query priming budget.',
        );

        // Clear the log and loop. A zero-query budget here is the
        // N+1 regression guard — any added query means the memo
        // tier missed and the resolver ran against the database.
        DB::flushQueryLog();

        for ($i = 0; $i < 10; $i++) {
            foreach (self::PERMISSION_NAMES as $action) {
                $manager->for($user)->can($action);
            }
        }

        $followupQueries = DB::getQueryLog();

        DB::disableQueryLog();

        self::assertCount(
            0,
            $followupQueries,
            'Subsequent can() calls must not hit the database — RBAC resolution cache missed.',
        );
    }

    /**
     * Seed the `editor` role with five attached permissions and return a
     * `StubIdentity` assigned to that role.
     *
     * @return \Tests\Feature\Stubs\StubIdentity
     */
    private function makeEditorWithFivePermissions(): StubIdentity
    {
        $role = Role::create([
            'id'         => (string) Str::uuid(),
            'name'       => 'editor',
            'guard_name' => 'web',
        ]);

        foreach (self::PERMISSION_NAMES as $name) {
            $permission = Permission::create([
                'id'         => (string) Str::uuid(),
                'name'       => $name,
                'guard_name' => 'web',
            ]);
            $role->permissions()->attach($permission->getKey());
        }

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $user->assignRole('editor');

        return $user;
    }
}
