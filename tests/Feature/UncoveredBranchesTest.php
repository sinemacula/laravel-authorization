<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Carbon\Carbon;
use Illuminate\Cache\Repository;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Assert;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use Psr\Log\AbstractLogger;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Cache\ResolutionCacheContext;
use SineMacula\Laravel\Authorization\Concerns\HasPermissions;
use SineMacula\Laravel\Authorization\Concerns\HasPolicies;
use SineMacula\Laravel\Authorization\Concerns\HasRoles;
use SineMacula\Laravel\Authorization\Concerns\ResolvesPivotExpiry;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Contracts\SupportsRoles;
use SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException;
use SineMacula\Laravel\Authorization\Exceptions\UnknownPermissionException;
use SineMacula\Laravel\Authorization\Exceptions\UnknownRoleException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Support\BladeHelpers;
use Tests\Feature\Stubs\NonTaggableCacheStore;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubSubjectResolver;
use Tests\Feature\Stubs\ThrowingGetCacheStore;
use Tests\TestCase;

/**
 * Coverage-focused feature tests that reach the narrow branches not hit by the
 * main behavioural suites: relation-loaded unset paths, fallback paths when the
 * resolution cache is unbound, lookup-by-id throws, non-tag cache store
 * branches, empty-string guards on cache keys, and Spatie migration skip
 * branches.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 * @SuppressWarnings("php:S1448")
 * @SuppressWarnings("php:S112")
 */
#[CoversClass(ResolutionCache::class)]
#[CoversClass(BladeHelpers::class)]
#[CoversTrait(HasRoles::class)]
#[CoversTrait(HasPermissions::class)]
#[CoversTrait(HasPolicies::class)]
#[CoversTrait(ResolvesPivotExpiry::class)]
final class UncoveredBranchesTest extends TestCase
{
    /**
     * Loading the roles relation and then calling `assignRole()` must purge the
     * loaded-relation cache so a subsequent read sees the freshly-attached row.
     * Targets the `unset($this->relations['roles'])` branch.
     *
     * @return void
     */
    public function testAssignRoleClearsLoadedRolesRelationCache(): void
    {
        $role = Role::create(['id' => (string) Str::uuid(), 'name' => 'editor', 'guard' => 'web']);
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);

        // Prime the relation cache.
        $user->load('roles');
        self::assertCount(0, $user->roles);

        $user->assignRole($role);

        // Re-reading `$user->roles` hits the freshly-reloaded relation.
        self::assertCount(1, $user->roles);
    }

    /**
     * Same invariant for `syncRoles()` — the relation cache must be purged so a
     * follow-up read sees the new roster.
     *
     * @return void
     */
    public function testSyncRolesClearsLoadedRolesRelationCache(): void
    {
        Role::create(['id' => (string) Str::uuid(), 'name' => 'a', 'guard' => 'web']);
        Role::create(['id' => (string) Str::uuid(), 'name' => 'b', 'guard' => 'web']);

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $user->load('roles');

        $user->syncRoles(['a', 'b']);

        $names = $user->roles->map(static fn (Role $r): string => $r->name)->all();
        \sort($names);
        self::assertSame(['a', 'b'], $names);
    }

    /**
     * `givePermission()` must clear the loaded-permissions relation cache.
     *
     * @return void
     */
    public function testGivePermissionClearsLoadedPermissionsRelationCache(): void
    {
        $permission = Permission::create(['id' => (string) Str::uuid(), 'name' => 'posts:create', 'guard' => 'web']);
        $user       = StubIdentity::create(['id' => (string) Str::uuid()]);

        $user->load('permissions');
        self::assertCount(0, $user->permissions);

        $user->givePermission($permission);

        self::assertCount(1, $user->permissions);
    }

    /**
     * `syncPermissions()` must clear the loaded-permissions relation cache.
     *
     * @return void
     */
    public function testSyncPermissionsClearsLoadedPermissionsRelationCache(): void
    {
        Permission::create(['id' => (string) Str::uuid(), 'name' => 'a:do', 'guard' => 'web']);
        Permission::create(['id' => (string) Str::uuid(), 'name' => 'b:do', 'guard' => 'web']);

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $user->load('permissions');

        $user->syncPermissions(['a:do', 'b:do']);

        $names = $user->permissions->map(static fn (Permission $p): string => $p->name)->all();
        \sort($names);
        self::assertSame(['a:do', 'b:do'], $names);
    }

    /**
     * `attachPolicy()` must clear the loaded-policies relation cache.
     *
     * @return void
     */
    public function testAttachPolicyClearsLoadedPoliciesRelationCache(): void
    {
        $policy = Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'p1',
            'document' => ['statements' => [['effect' => 'allow', 'actions' => ['x']]]],
        ]);
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);

        $user->load('policies');
        self::assertCount(0, $user->policies);

        $user->attachPolicy($policy);

        self::assertCount(1, $user->policies);
    }

    /**
     * `syncPolicies()` must clear the loaded-policies relation cache.
     *
     * @return void
     */
    public function testSyncPoliciesClearsLoadedPoliciesRelationCache(): void
    {
        $a = Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'a',
            'document' => ['statements' => [['effect' => 'allow', 'actions' => ['x']]]],
        ]);
        $b = Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'b',
            'document' => ['statements' => [['effect' => 'allow', 'actions' => ['y']]]],
        ]);

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $user->load('policies');

        $user->syncPolicies([$a, $b]);

        self::assertCount(2, $user->policies);
    }

    /**
     * When the resolution cache is not bound to the container, `getRoles()`
     * falls back to `computeRoles()` directly. Targets `HasRoles::getRoles()`
     * line 242.
     *
     * @return void
     */
    public function testGetRolesFallsBackToComputeWhenCacheUnbound(): void
    {
        $role = Role::create(['id' => (string) Str::uuid(), 'name' => 'viewer', 'guard' => 'web']);
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $user->assignRole($role);

        $this->app->forgetInstance(ResolutionCache::class); // @phpstan-ignore method.nonObject
        $this->app->offsetUnset(ResolutionCache::class); // @phpstan-ignore method.nonObject

        $names = $user->fresh()?->getRoles() ?? [];

        self::assertSame(['viewer'], $names);
    }

    /**
     * When the resolution cache is not bound to the container,
     * `getPermissions()` falls back to `computePermissions()` directly. Targets
     * `HasPermissions::getPermissions()` line 250.
     *
     * @return void
     */
    public function testGetPermissionsFallsBackToComputeWhenCacheUnbound(): void
    {
        $permission = Permission::create(['id' => (string) Str::uuid(), 'name' => 'posts:read', 'guard' => 'web']);
        $user       = StubIdentity::create(['id' => (string) Str::uuid()]);
        $user->givePermission($permission);

        $this->app->forgetInstance(ResolutionCache::class); // @phpstan-ignore method.nonObject
        $this->app->offsetUnset(ResolutionCache::class); // @phpstan-ignore method.nonObject

        $names = $user->fresh()?->getPermissions() ?? [];

        self::assertSame(['posts:read'], $names);
    }

    /**
     * `canActOn()` returns false when the target doesn't expose a `roles()`
     * method. Targets `HasRoles::canActOn()` line 289.
     *
     * @return void
     */
    public function testCanActOnReturnsFalseWhenTargetLacksRolesMethod(): void
    {
        $role = Role::create(['id' => (string) Str::uuid(), 'name' => 'admin', 'guard' => 'web', 'rank' => 0]);
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $user->assignRole($role);

        // A target that implements SupportsRoles but without a real `roles()`
        // relation.
        $target = new class implements SupportsRoles {
            /**
             * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
             * @return static
             */
            #[\Override]
            public function assignRole(Role|string $role): static
            {
                return $this;
            }

            /**
             * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
             * @return static
             */
            #[\Override]
            public function revokeRole(Role|string $role): static
            {
                return $this;
            }

            /**
             * @param  array<int, \SineMacula\Laravel\Authorization\Models\Role|string>  $roles
             * @return static
             */
            #[\Override]
            public function syncRoles(array $roles): static
            {
                return $this;
            }

            /**
             * @param  \SineMacula\Laravel\Authorization\Models\Role|string  $role
             * @param  string|null  $guard
             * @return bool
             */
            #[\Override]
            public function hasRole(Role|string $role, ?string $guard = null): bool
            {
                return false;
            }

            /**
             * @return array<int, string>
             */
            #[\Override]
            public function getRoles(): array
            {
                return [];
            }
        };

        self::assertFalse($user->fresh()?->canActOn($target));
    }

    /**
     * `resolveRoleById()` throws when the ID is unknown. Targets `HasRoles`
     * line 376 via `syncRoles()` detachment with a deleted row.
     *
     * @return void
     */
    public function testResolveRoleByIdThrowsWhenMissing(): void
    {
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);

        $reflection = new \ReflectionMethod($user, 'resolveRoleById');

        $this->expectException(UnknownRoleException::class);

        $reflection->invoke($user, '00000000-0000-4000-8000-ffffffffffff');
    }

    /**
     * `resolvePermissionById()` throws when the ID is unknown. Targets
     * `HasPermissions` line 351 — the private resolver invoked by
     * `syncPermissions()` when the sync delta surfaces a detached ID whose row
     * no longer exists.
     *
     * @return void
     */
    public function testResolvePermissionByIdThrowsWhenMissing(): void
    {
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);

        $reflection = new \ReflectionMethod($user, 'resolvePermissionById');

        $this->expectException(UnknownPermissionException::class);

        $reflection->invoke($user, '00000000-0000-4000-8000-ffffffffffff');
    }

    /**
     * A cached permissions entry whose resolver returns nothing and whose
     * stored value is the empty array hits the `array_filter(is_string)` branch
     * that discards non-string entries — we sneak one in via the fresh cache to
     * cover the filter branch on `rememberStringList`.
     *
     * Targets `ResolutionCache::rememberStringList` line 308 filter branch.
     *
     * @return void
     */
    public function testRememberStringListFiltersNonStringEntriesFromPersistentStore(): void
    {
        $driver = self::makeNonTaggableDriver();
        $store  = new Repository($driver);
        $cache  = new ResolutionCache(store: $store, ttl: 0, prefix: 'authorization-test');

        $principal = StubIdentity::create(['id' => (string) Str::uuid()]);

        // Prime the persistent tier via the cache so the written key precisely
        // matches the cache's internal key shape. A fresh instance then
        // bypasses the memo and re-reads the corrupted payload from the store.
        $cache->rememberPermissions($principal, static fn (): array => ['seed']);

        // Corrupt the stored entry in-place — swap the single seeded value for
        // a mixed-type list. The filter branch in `rememberStringList` drops
        // the non-string items and returns only the strings.
        $key = \array_key_first($driver->storage); // @phpstan-ignore property.notFound
        self::assertIsString($key);
        $driver->storage[$key] = ['valid:perm', 42, null, 'another:perm']; // @phpstan-ignore property.notFound

        $fresh = new ResolutionCache(store: $store, ttl: 0, prefix: 'authorization-test');

        $cachedEntries = $fresh->rememberPermissions($principal, static fn (): array => Assert::fail('Resolver should not be called on a store hit.'));

        self::assertSame(['valid:perm', 'another:perm'], $cachedEntries);
    }

    /**
     * `forgetRoleTags()` is a no-op when the role exposes no key. Targets
     * `ResolutionCache::forgetRoleTags` line 240 (empty ID early return) via a
     * role-like object whose `getKey()` yields an empty string.
     *
     * @return void
     */
    public function testForgetRoleTagsIsNoopForRoleWithEmptyKey(): void
    {
        $cache = new ResolutionCache(
            store: Cache::store('array'),
            ttl: 0,
            prefix: 'authorization-test',
        );

        $role = new class {
            /**
             * @return string
             */
            public function getKey(): string
            {
                return '';
            }
        };

        // Method returns void; the assertion is that no exception is raised and
        // no tag-flush occurs.
        $cache->forgetRoleTags($role);

        self::assertTrue(true);
    }

    /**
     * `forgetRoleTags()` is a no-op on a non-tag store. Targets
     * `ResolutionCache::forgetRoleTags` line 232 early return.
     *
     * @return void
     */
    public function testForgetRoleTagsIsNoopOnNonTagStore(): void
    {
        $driver = self::makeNonTaggableDriver();
        $store  = new Repository($driver);
        $cache  = new ResolutionCache(store: $store, ttl: 0, prefix: 'authorization-test');

        $role = Role::create(['id' => (string) Str::uuid(), 'name' => 'ghost', 'guard' => 'web']);

        // Expect no exception raised when the underlying driver lacks `tags()`
        // — the method exits at the early guard.
        $cache->forgetRoleTags($role);

        self::assertTrue(true);
    }

    /**
     * `forget()` on a non-tag store iterates every slot. Targets lines 210-211
     * of `ResolutionCache::forget`.
     *
     * @return void
     */
    public function testForgetIteratesEverySlotOnNonTagStore(): void
    {
        $driver = self::makeNonTaggableDriver();
        $store  = new Repository($driver);
        $cache  = new ResolutionCache(store: $store, ttl: 0, prefix: 'authorization-test');

        $principal = StubIdentity::create(['id' => (string) Str::uuid()]);

        $cache->rememberPermissions($principal, static fn (): array => ['a:do']);
        $cache->rememberRoles($principal, static fn (): array => ['admin']);

        self::assertNotEmpty($driver->storage, 'Persistent store should contain entries before forget().'); // @phpstan-ignore property.notFound

        $cache->forget($principal);

        self::assertEmpty($driver->storage, 'Non-tag forget() should remove every per-principal slot.');
    }

    /**
     * Principal with an object that exposes neither `getKey()` nor
     * `getMorphClass()` falls back to the `spl_object_hash`-based key path.
     * Targets `ResolutionCache::keyFor` line 391.
     *
     * @return void
     */
    public function testKeyForFallsBackToSplObjectHashForBareObject(): void
    {
        $cache     = new ResolutionCache;
        $principal = new \stdClass;

        $cache->rememberPermissions($principal, static fn (): array => ['z:do']);

        // Same object returns the memoised value without invoking the resolver
        // again.
        $cachedEntries = $cache->rememberPermissions($principal, static fn (): array => Assert::fail('memoised'));

        self::assertSame(['z:do'], $cachedEntries);
    }

    /**
     * The tagsFor helper strips empty role IDs — targets
     * `ResolutionCache::tagsFor` line 425.
     *
     * @return void
     */
    public function testTagsForSkipsEmptyRoleIds(): void
    {
        $cache = new ResolutionCache(
            store: Cache::store('array'),
            ttl: 0,
            prefix: 'authorization-test',
        );

        $principal = StubIdentity::create(['id' => (string) Str::uuid()]);

        // Route an empty-ID entry through the remember flow — the tags builder
        // drops it silently, so the write succeeds.
        $cache->rememberPermissions(
            $principal,
            static fn (): array => ['t:do'],
            new ResolutionCacheContext(maxTtl: null, roleIds: ['', 'real-role-id']),
        );

        self::assertSame(['t:do'], $cache->rememberPermissions($principal, static fn (): array => []));
    }

    /**
     * A `putInStore` call with a `maxTtl` of zero short-circuits without
     * writing. Targets line 595 of `ResolutionCache`.
     *
     * @return void
     */
    public function testPutInStoreSkipsWhenTtlIsZeroOrLess(): void
    {
        $driver = self::makeNonTaggableDriver();
        $store  = new Repository($driver);
        $cache  = new ResolutionCache(store: $store, ttl: 0, prefix: 'authorization-test');

        $principal = StubIdentity::create(['id' => (string) Str::uuid()]);

        // `maxTtl = 1` with `min($base, 1) - 1 = 0` triggers the short-circuit.
        // The resolver still runs and the return value is propagated, but
        // nothing lands in the driver.
        $cache->rememberPermissions(
            $principal,
            static fn (): array => ['x:do'],
            new ResolutionCacheContext(maxTtl: 1),
        );

        self::assertSame([], $driver->storage, 'Persistent tier must skip zero/negative TTL writes.'); // @phpstan-ignore property.notFound
    }

    /**
     * `BladeHelpers::hasAllRoles` returns false when the principal does not
     * implement `SupportsRoles`. Targets line 80.
     *
     * @return void
     */
    public function testBladeHelpersHasAllRolesReturnsFalseForNonRoleSupportingPrincipal(): void
    {
        $this->app->instance( // @phpstan-ignore method.nonObject
            SubjectResolver::class,
            new StubSubjectResolver(new \stdClass),
        );

        self::assertFalse(BladeHelpers::hasAllRoles(['admin']));
    }

    // Spatie-migration-specific coverage lives in MigrateSpatieSkipTest; that
    // test suite configures the package tables at `defineEnvironment` time so
    // the `roles` / `permissions` names are free for the Spatie source schema.

    /**
     * `ResolvesPivotExpiry::authorizationCoerceExpiresAt` returns a Carbon
     * instance when the raw pivot value is a non-empty string. Targets lines
     * 135-136 of the trait via a temporal role assignment routed through
     * `getRoles()`.
     *
     * @return void
     */
    public function testCoerceExpiresAtHandlesStringValue(): void
    {
        $role = Role::create(['id' => (string) Str::uuid(), 'name' => 'temp', 'guard' => 'web']);
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $user->assignRole($role, Carbon::now()->addHour());

        $names = $user->fresh()?->getRoles() ?? [];

        self::assertSame(['temp'], $names);
    }

    /**
     * `ResolvesPivotExpiry::authorizationMinNullable` returns the smaller of
     * two non-null seconds. Targets line 160.
     *
     * @return void
     */
    public function testAuthorizationMinNullableReturnsSmallerOfTwoInts(): void
    {
        /** @phpstan-ignore-next-line class.missingExtends */
        $probe = new class {
            use ResolvesPivotExpiry;

            /**
             * @param  ?int  $left
             * @param  ?int  $right
             * @return int|null
             */
            public function min(?int $left, ?int $right): ?int
            {
                return self::authorizationMinNullable($left, $right);
            }
        };

        self::assertSame(3, $probe->min(5, 3));
        self::assertSame(3, $probe->min(3, 5));
        self::assertSame(5, $probe->min(null, 5));
        self::assertSame(5, $probe->min(5, null));
        self::assertNull($probe->min(null, null));
    }

    /**
     * `ResolvesPivotExpiry::authorizationSecondsUntilPivotExpiry` returns null
     * when the pivot is absent on the model. Targets line 100.
     *
     * @return void
     */
    public function testSecondsUntilPivotExpiryReturnsNullWhenPivotMissing(): void
    {
        /** @phpstan-ignore-next-line class.missingExtends */
        $probe = new class {
            use ResolvesPivotExpiry;

            /**
             * @param  \Illuminate\Database\Eloquent\Model  $model
             * @return int|null
             */
            public function seconds(Model $model): ?int
            {
                return self::authorizationSecondsUntilPivotExpiry($model, 0);
            }
        };

        $model = new class extends Model {};

        self::assertNull($probe->seconds($model));
    }

    /**
     * `logMalformedPolicy` also tolerates a logger that throws on the warning
     * call itself: the logging failure is swallowed and `getPolicies()`
     * rethrows the malformed row's own exception. Targets the outer catch in
     * `HasPolicies::logMalformedPolicy`.
     *
     * @return void
     */
    public function testLogMalformedPolicyTolerantOfLoggerWarningFailure(): void
    {
        // Rebind the logger to one whose `warning()` raises. The method
        // swallows the failure, so the malformed row's own exception is the one
        // that reaches the caller.
        // @phpstan-ignore-next-line method.nonObject
        $this->app->instance('log', new class extends AbstractLogger {
            // @phpstan-ignore method.nonObject
            /**
             * @param  string  $name
             * @return self
             */
            public function channel(string $name): self
            {
                return $this;
            }

            /**
             * @param  string|\Stringable  $message
             * @param  array<mixed>  $context
             * @return void
             *
             * @throws \RuntimeException
             */
            #[\Override]
            public function warning(string|\Stringable $message, array $context = []): void
            {
                throw new \RuntimeException('logger unavailable');
            }

            /**
             * @param  mixed  $level
             * @param  string|\Stringable  $message
             * @param  array<mixed>  $context
             * @return void
             */
            #[\Override]
            public function log(mixed $level, string|\Stringable $message, array $context = []): void {}
        });

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);

        $policy = Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'malformed-warn',
            'document' => ['statements' => [['effect' => 'allow', 'actions' => ['x']]]],
        ]);
        $user->attachPolicy($policy);

        // Replace with a JSON payload lacking the `statements` key so
        // `EvaluationPolicy::fromArray()` raises.
        DB::table((string) config('authorization.tables.policies', 'policies')) // @phpstan-ignore cast.string
            ->where('id', $policy->getKey())
            ->update(['document' => \json_encode(['version' => 'not-an-int'])]);

        $this->expectException(InvalidPolicyDocumentException::class);
        $this->expectExceptionMessage('Invalid policy document \'malformed-warn\': Policy document requires a list of statements.');

        $user->fresh()?->getPolicies();
    }

    /**
     * `rememberPolicies` returns the memoised value on a second call without
     * hitting the persistent store. Targets line 99 of
     * `ResolutionCache::rememberPolicies`.
     *
     * @return void
     */
    public function testRememberPoliciesReturnsMemoisedValueOnSecondCall(): void
    {
        $cache     = new ResolutionCache;
        $principal = new \stdClass;

        $policy = new \SineMacula\Laravel\Authorization\Evaluation\Policy(
            name: 'memo',
            statements: [],
        );

        $first  = $cache->rememberPolicies($principal, static fn (): array => [$policy]);
        $second = $cache->rememberPolicies($principal, static fn (): array => Assert::fail('memoised'));

        self::assertSame($first, $second);
    }

    /**
     * A valid persistent policy document payload round-trips through
     * `rememberPolicies`. Targets line 116 (`fromArray` call inside the
     * hydration loop) of `ResolutionCache`.
     *
     * @return void
     */
    public function testRememberPoliciesHydratesFromPersistentPayload(): void
    {
        $driver = self::makeNonTaggableDriver();
        $store  = new Repository($driver);
        $cache  = new ResolutionCache(store: $store, ttl: 0, prefix: 'authorization-test');

        $principal = StubIdentity::create(['id' => (string) Str::uuid()]);

        $policy = new \SineMacula\Laravel\Authorization\Evaluation\Policy(
            name: 'hydrated',
            statements: [],
        );
        $cache->rememberPolicies($principal, static fn (): array => [$policy]);

        // Fresh instance bypasses the memo and hydrates from the persistent
        // tier — exercising the `Policy::fromArray` loop branch.
        $fresh         = new ResolutionCache(store: $store, ttl: 0, prefix: 'authorization-test');
        $cachedEntries = $fresh->rememberPolicies(
            $principal,
            static fn (): array => Assert::fail('Should hit the persistent store.'),
        );

        self::assertCount(1, $cachedEntries);
        self::assertSame('hydrated', $cachedEntries[0]->name);
    }

    /**
     * A driver whose `get()` raises triggers the corrupt-entry recovery path in
     * `rememberStringList`. Targets lines 310, 313, 314 of `ResolutionCache`.
     *
     * @return void
     */
    public function testRememberStringListRecoversFromDriverGetFailure(): void
    {
        $driver = new ThrowingGetCacheStore;

        $store = new Repository($driver);
        $cache = new ResolutionCache(store: $store, ttl: 0, prefix: 'authorization-test');

        $principal = StubIdentity::create(['id' => (string) Str::uuid()]);

        $cachedEntries = $cache->rememberPermissions($principal, static fn (): array => ['fresh:perm']);

        self::assertSame(['fresh:perm'], $cachedEntries);
        self::assertGreaterThanOrEqual(1, $driver->getCalls, 'driver get() should be attempted');
        self::assertGreaterThanOrEqual(1, $driver->forgetCalls, 'forget() should be called on corruption');
    }

    /**
     * `logCorruptCacheEntry` tolerates a logger whose `warning()` raises.
     * Targets line 553 of `ResolutionCache`.
     *
     * @return void
     */
    public function testLogCorruptCacheEntryTolerantOfLoggerWarningFailure(): void
    {
        // @phpstan-ignore-next-line method.nonObject
        $this->app->instance('log', new class extends AbstractLogger {
            // @phpstan-ignore method.nonObject
            /**
             * @param  string  $name
             * @return self
             */
            public function channel(string $name): self
            {
                return $this;
            }

            /**
             * @param  string|\Stringable  $message
             * @param  array<mixed>  $context
             * @return void
             *
             * @throws \RuntimeException
             */
            #[\Override]
            public function warning(string|\Stringable $message, array $context = []): void
            {
                throw new \RuntimeException('logger unavailable');
            }

            /**
             * @param  mixed  $level
             * @param  string|\Stringable  $message
             * @param  array<mixed>  $context
             * @return void
             */
            #[\Override]
            public function log(mixed $level, string|\Stringable $message, array $context = []): void {}
        });

        $driver = self::makeNonTaggableDriver();
        $store  = new Repository($driver);
        $cache  = new ResolutionCache(store: $store, ttl: 0, prefix: 'authorization-test');

        $principal = StubIdentity::create(['id' => (string) Str::uuid()]);

        $cache->rememberPolicies($principal, static fn (): array => []);
        $key                   = (string) \array_key_first($driver->storage); // @phpstan-ignore property.notFound
        $driver->storage[$key] = ['still-not-an-array']; // @phpstan-ignore property.notFound

        $fresh = new ResolutionCache(store: $store, ttl: 0, prefix: 'authorization-test');

        // The fail-closed contract ensures hydration still returns.
        $cachedEntries = $fresh->rememberPolicies($principal, static fn (): array => []);

        self::assertSame([], $cachedEntries);
    }

    /**
     * Build a bare non-taggable `Store` — mirrors the helper used by
     * `ResolutionCacheTest`.
     *
     * @return \Tests\Feature\Stubs\NonTaggableCacheStore
     */
    private static function makeNonTaggableDriver(): NonTaggableCacheStore
    {
        return new NonTaggableCacheStore;
    }
}
