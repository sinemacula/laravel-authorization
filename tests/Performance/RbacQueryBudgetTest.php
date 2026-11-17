<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Contracts\PolicyResolver;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\BoundaryService;
use SineMacula\Laravel\Authorization\Services\GuardrailService;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResolvedTenant;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubSubjectResolver;
use Tests\Feature\Stubs\StubTenant;
use Tests\Feature\Stubs\StubTenantTree;
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
 * A permission allows a check on a resource only where the grant it came from
 * reaches the resource. That reach costs no query of its own: the permissions
 * are resolved per scope, keyed by the scope's tenant and application, so each
 * tenant's entry already holds only the grants that reach it, and a check on a
 * resource of a tenant reads that tenant's entry. The budgets are unchanged:
 * five queries for one scope's permissions, and none once every scope a check
 * reads is warm.
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
        $config->set('authorization.cache.ttl', 300);
        $config->set('authorization.cache.prefix', 'authorization-rbac-budget');

        $app->forgetInstance(ResolutionCache::class);
        $app->forgetInstance(PolicyResolver::class);

        (new AuthorizationServiceProvider($app))->register();
    }

    /**
     * A user carrying a role with five permissions must not emit a database
     * query on any `can()` beyond the first. The initial resolution loads
     * roles, role permissions, direct permissions, attached policies, the
     * permission boundaries and the guardrails — one query each for the caps,
     * since they cap every check and are read apart from the policies, so a
     * custom policy resolver can never drop them — and every subsequent `can()`
     * for the same principal during the same request is served from cache.
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

        // Prime the cache — the first `can()` pays the full resolution cost.
        // Budget: at most eight queries (roles, role-permissions, direct
        // permissions, attached policies, the permission boundaries and the
        // guardrails, each read in one query with their documents, plus up to
        // two guard/tenant lookups executed inside the trait helpers). This is
        // loose on purpose — the hard assertion below is the zero-query floor
        // on subsequent calls.
        DB::enableQueryLog();
        DB::flushQueryLog();

        $manager->for($user)->can(self::PERMISSION_NAMES[0]);

        $primingQueries = DB::getQueryLog();
        self::assertLessThanOrEqual(
            8,
            \count($primingQueries),
            'Initial RBAC resolution exceeded the 8-query priming budget.',
        );

        // Clear the log and loop. A zero-query budget here is the N+1
        // regression guard — any added query means the memo tier missed and the
        // resolver ran against the database.
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
     * Resolving an identity's permissions takes the same number of queries for
     * one role one level deep as for four roles four levels deep: the grants,
     * the hierarchy and the roles' permissions are each read once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testResolutionQueriesDoNotGrowWithRolesOrDepth(): void
    {
        $resolve = static fn (StubIdentity $user): array => $user->getPermissions();

        $shallowQueries = $this->coldQueries(self::identityHolding(roles: 1, depth: 2), $resolve);
        $deepQueries    = $this->coldQueries(self::identityHolding(roles: 4, depth: 4), $resolve);

        self::assertLessThanOrEqual(5, \count($deepQueries), 'Permission resolution exceeded its five-query budget.');
        self::assertCount(\count($shallowQueries), $deepQueries, 'Permission resolution grew with the number of roles or the depth of the hierarchy.');
    }

    /**
     * A cold check through the manager takes the same 13 queries for one role
     * as for four roles four levels deep, every role carrying a policy, with a
     * policy and a boundary on the identity and a guardrail on the platform.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testColdCheckQueriesDoNotGrowWithRolesOrDepth(): void
    {
        $actor = StubIdentity::create(['id' => (string) Str::uuid()]);

        $actor->givePermission(Permission::create(['name' => PackagePermissions::GUARDRAIL_MANAGE, 'guard' => 'web']));

        $this->app?->make(GuardrailService::class)->set(self::policy('guardrail', 'allow', '*'), null, ActingContext::for($actor));

        $check = function (StubIdentity $user): void {
            $manager = $this->app?->make(AuthorizationManager::class);

            self::assertTrue($manager?->for($user)->can('chain-' . Reference::of($user)->id . '-0-0:read'));
        };

        $shallowQueries = $this->coldQueries(self::identityHolding(roles: 1, depth: 1), $check);
        $deepQueries    = $this->coldQueries(self::identityHolding(roles: 4, depth: 4), $check);

        self::assertLessThanOrEqual(13, \count($deepQueries), "A cold check exceeded its 13-query budget:\n" . \implode("\n", $deepQueries));
        self::assertCount(\count($shallowQueries), $deepQueries, "A cold check grew with the number of roles or the depth of the hierarchy:\n" . \implode("\n", $deepQueries));
    }

    /**
     * Checks on resources of the active tenant, of a tenant below it and of
     * none, each decided in its own scope, and on one of a sibling tenant,
     * refused at the tenant stage once the platform scope finds no grant that
     * admits it, read each scope's resolution once: once every scope is warm,
     * checking them again in the same request emits no query.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testChecksOnTenantOwnedResourcesEmitNoQueryOnceEachScopeIsWarm(): void
    {
        $create                           = static fn (string $id): StubTenant => StubTenant::query()->create(['id' => $id, 'name' => $id]);
        [$org, $account, $team, $sibling] = \array_map($create, ['org', 'account', 'team', 'sibling']);

        $this->app?->instance(TenantTree::class, (new StubTenantTree)
            ->put(Reference::of($account), Reference::of($org))
            ->put(Reference::of($team), Reference::of($account))
            ->put(Reference::of($sibling), Reference::of($org)));

        $user = $this->makeEditorWithFivePermissions();

        $user->givePermission(Permission::create(['name' => 'posts:archive', 'guard' => 'web']), null, $org);

        $this->app?->instance(SubjectResolver::class, new StubSubjectResolver($user, $account));
        $this->app?->forgetInstance(ResolvedTenant::class);

        $resources = [
            ResourceReference::record('posts', '1', Reference::of($account)),
            ResourceReference::record('posts', '2', Reference::of($team)),
            ResourceReference::record('posts', '3'),
            null,
        ];

        $check = static function () use ($resources): array {
            $allowed = [];

            foreach ($resources as $resource) {
                foreach ([...self::PERMISSION_NAMES, 'posts:archive'] as $action) {
                    $allowed[] = Authorization::can($action, $resource);
                }
            }

            return $allowed;
        };

        $outside = ResourceReference::record('posts', '4', Reference::of($sibling));

        self::assertNotContains(false, $check());
        self::assertFalse(Authorization::can('posts:archive', $outside));

        DB::enableQueryLog();
        DB::flushQueryLog();

        self::assertNotContains(false, $check());
        self::assertFalse(Authorization::can('posts:archive', $outside));

        $queries = DB::getQueryLog();

        DB::disableQueryLog();

        self::assertCount(0, $queries, 'Checks on tenant-owned resources hit the database once every scope was warm.');
    }

    /**
     * Create an identity holding the given number of roles, each at the bottom
     * of its own chain of the given depth with a permission and a policy at
     * every level, and a policy and a boundary of its own.
     *
     * @param  int  $roles
     * @param  int  $depth
     * @return \Tests\Feature\Stubs\StubIdentity
     *
     * @throws \Throwable
     */
    private static function identityHolding(int $roles, int $depth): StubIdentity
    {
        $id   = (string) Str::uuid();
        $user = StubIdentity::create(['id' => $id]);

        for ($r = 0; $r < $roles; $r++) {
            $parent = null;

            for ($d = 0; $d < $depth; $d++) {
                $name   = "chain-{$id}-{$r}-{$d}";
                $parent = Role::create(['name' => $name, 'guard' => 'web', 'parent_id' => $parent?->getKey()]);

                $parent->permissions()->attach(Permission::create(['name' => "{$name}:read", 'guard' => 'web'])->getKey());
                $parent->attachPolicy(self::policy($name, 'allow', "{$name}:write"));
            }

            \assert($parent instanceof Role);

            $user->assignRole($parent);
        }

        $user->attachPolicy(self::policy("deny-{$id}", 'deny', 'posts:delete'));

        BoundaryService::instance()?->set($user, self::policy("boundary-{$id}", 'allow', '*'));

        return $user;
    }

    /**
     * Return a policy of one statement with the effect on the action.
     *
     * @param  string  $name
     * @param  string  $effect
     * @param  string  $action
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     */
    private static function policy(string $name, string $effect, string $action): Policy
    {
        return Policy::create(['name' => $name, 'document' => ['statements' => [['effect' => $effect, 'actions' => [$action]]]]]);
    }

    /**
     * Return the queries the callback runs on a fresh copy of the identity,
     * with the resolution cache and every scoped instance cold.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $user
     * @param  \Closure(\Tests\Feature\Stubs\StubIdentity): mixed  $run
     * @return list<string>
     */
    private function coldQueries(StubIdentity $user, \Closure $run): array
    {
        $app = $this->app;
        self::assertNotNull($app, 'Testbench application must be booted by setUp().');

        $app->make('cache')->store('array')->clear();
        $app->forgetScopedInstances();

        $fresh = StubIdentity::query()->whereKey($user->getKey())->firstOrFail();

        DB::enableQueryLog();
        DB::flushQueryLog();

        $run($fresh);

        /** @var list<string> $queries */
        $queries = \array_column(DB::getQueryLog(), 'query');

        DB::disableQueryLog();

        return $queries;
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
            'id'    => (string) Str::uuid(),
            'name'  => 'editor',
            'guard' => 'web',
        ]);

        foreach (self::PERMISSION_NAMES as $name) {
            $permission = Permission::create([
                'id'    => (string) Str::uuid(),
                'name'  => $name,
                'guard' => 'web',
            ]);
            $role->permissions()->attach($permission->getKey());
        }

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $user->assignRole('editor');

        return $user;
    }
}
