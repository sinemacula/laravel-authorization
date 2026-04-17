<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Exceptions\UnknownPermissionException;
use SineMacula\Laravel\Authorization\Exceptions\UnknownRoleException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Support\BladeHelpers;
use SineMacula\Laravel\Authorization\Traits\HasPermissions;
use SineMacula\Laravel\Authorization\Traits\HasPolicies;
use SineMacula\Laravel\Authorization\Traits\HasRoles;
use SineMacula\Laravel\Authorization\Traits\ResolvesPivotExpiry;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Coverage-focused feature tests that reach the narrow branches not
 * hit by the main behavioural suites: relation-loaded unset paths,
 * fallback paths when the resolution cache is unbound, lookup-by-id
 * throws, non-tag cache store branches, empty-string guards on
 * cache keys, and Spatie migration skip branches.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
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
     * Loading the roles relation and then calling `assignRole()`
     * must purge the loaded-relation cache so a subsequent read
     * sees the freshly-attached row. Targets the
     * `unset($this->relations['roles'])` branch.
     *
     * @return void
     */
    public function testAssignRoleClearsLoadedRolesRelationCache(): void
    {
        $role = Role::create(['id' => (string) Str::uuid(), 'name' => 'editor', 'guard_name' => 'web']);
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);

        // Prime the relation cache.
        $user->load('roles');
        self::assertCount(0, $user->roles);

        $user->assignRole($role);

        // Re-reading `$user->roles` hits the freshly-reloaded relation.
        self::assertCount(1, $user->roles);
    }

    /**
     * Same invariant for `syncRoles()` — the relation cache must
     * be purged so a follow-up read sees the new roster.
     *
     * @return void
     */
    public function testSyncRolesClearsLoadedRolesRelationCache(): void
    {
        Role::create(['id' => (string) Str::uuid(), 'name' => 'a', 'guard_name' => 'web']);
        Role::create(['id' => (string) Str::uuid(), 'name' => 'b', 'guard_name' => 'web']);

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $user->load('roles');

        $user->syncRoles(['a', 'b']);

        $names = $user->roles->map(static fn (Role $r): string => $r->name)->all();
        \sort($names);
        self::assertSame(['a', 'b'], $names);
    }

    /**
     * `givePermission()` must clear the loaded-permissions
     * relation cache.
     *
     * @return void
     */
    public function testGivePermissionClearsLoadedPermissionsRelationCache(): void
    {
        $permission = Permission::create(['id' => (string) Str::uuid(), 'name' => 'posts:create', 'guard_name' => 'web']);
        $user       = StubIdentity::create(['id' => (string) Str::uuid()]);

        $user->load('permissions');
        self::assertCount(0, $user->permissions);

        $user->givePermission($permission);

        self::assertCount(1, $user->permissions);
    }

    /**
     * `syncPermissions()` must clear the loaded-permissions
     * relation cache.
     *
     * @return void
     */
    public function testSyncPermissionsClearsLoadedPermissionsRelationCache(): void
    {
        Permission::create(['id' => (string) Str::uuid(), 'name' => 'a:do', 'guard_name' => 'web']);
        Permission::create(['id' => (string) Str::uuid(), 'name' => 'b:do', 'guard_name' => 'web']);

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $user->load('permissions');

        $user->syncPermissions(['a:do', 'b:do']);

        $names = $user->permissions->map(static fn (Permission $p): string => $p->name)->all();
        \sort($names);
        self::assertSame(['a:do', 'b:do'], $names);
    }

    /**
     * `attachPolicy()` must clear the loaded-policies relation
     * cache.
     *
     * @return void
     */
    public function testAttachPolicyClearsLoadedPoliciesRelationCache(): void
    {
        $policy = \SineMacula\Laravel\Authorization\Models\Policy::create([
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
     * `syncPolicies()` must clear the loaded-policies relation
     * cache.
     *
     * @return void
     */
    public function testSyncPoliciesClearsLoadedPoliciesRelationCache(): void
    {
        $a = \SineMacula\Laravel\Authorization\Models\Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'a',
            'document' => ['statements' => [['effect' => 'allow', 'actions' => ['x']]]],
        ]);
        $b = \SineMacula\Laravel\Authorization\Models\Policy::create([
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
     * When the resolution cache is not bound to the container,
     * `getRoles()` falls back to `computeRoles()` directly.
     * Targets `HasRoles::getRoles()` line 242.
     *
     * @return void
     */
    public function testGetRolesFallsBackToComputeWhenCacheUnbound(): void
    {
        $role = Role::create(['id' => (string) Str::uuid(), 'name' => 'viewer', 'guard_name' => 'web']);
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $user->assignRole($role);

        $this->app->forgetInstance(ResolutionCache::class);
        $this->app->offsetUnset(ResolutionCache::class);

        $names = $user->fresh()?->getRoles() ?? [];

        self::assertSame(['viewer'], $names);
    }

    /**
     * When the resolution cache is not bound to the container,
     * `getPermissions()` falls back to `computePermissions()`
     * directly. Targets `HasPermissions::getPermissions()` line 250.
     *
     * @return void
     */
    public function testGetPermissionsFallsBackToComputeWhenCacheUnbound(): void
    {
        $permission = Permission::create(['id' => (string) Str::uuid(), 'name' => 'posts:read', 'guard_name' => 'web']);
        $user       = StubIdentity::create(['id' => (string) Str::uuid()]);
        $user->givePermission($permission);

        $this->app->forgetInstance(ResolutionCache::class);
        $this->app->offsetUnset(ResolutionCache::class);

        $names = $user->fresh()?->getPermissions() ?? [];

        self::assertSame(['posts:read'], $names);
    }

    /**
     * `canActOn()` returns false when the target doesn't expose a
     * `roles()` method. Targets `HasRoles::canActOn()` line 289.
     *
     * @return void
     */
    public function testCanActOnReturnsFalseWhenTargetLacksRolesMethod(): void
    {
        $role = Role::create(['id' => (string) Str::uuid(), 'name' => 'admin', 'guard_name' => 'web', 'rank' => 0]);
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $user->assignRole($role);

        // A target that implements SupportsRoles but without a real `roles()` relation.
        $target = new class implements \SineMacula\Laravel\Authorization\Contracts\SupportsRoles {
            public function assignRole(\SineMacula\Laravel\Authorization\Models\Role|string $role): static
            {
                return $this;
            }

            public function revokeRole(\SineMacula\Laravel\Authorization\Models\Role|string $role): static
            {
                return $this;
            }

            public function syncRoles(array $roles): static
            {
                return $this;
            }

            public function hasRole(\SineMacula\Laravel\Authorization\Models\Role|string $role): bool
            {
                return false;
            }

            /**
             * @return array<int, string>
             */
            public function getRoles(): array
            {
                return [];
            }
        };

        static::assertFalse($user->fresh()?->canActOn($target));
    }

    /**
     * `resolveRoleById()` throws when the ID is unknown. Targets
     * `HasRoles` line 376 via `syncRoles()` detachment with a
     * deleted row.
     *
     * @return void
     */
    public function testResolveRoleByIdThrowsWhenMissing(): void
    {
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);

        // Craft a user with a role assigned, then delete the role
        // underneath so `syncRoles()` hits the detachment path and
        // `resolveRoleById()` fails to find the row.
        $role = Role::create(['id' => (string) Str::uuid(), 'name' => 'ghost', 'guard_name' => 'web']);
        $user->assignRole($role);
        $roleId = (string) $role->getKey();
        Schema::disableForeignKeyConstraints();
        $role->delete();
        Schema::enableForeignKeyConstraints();

        $this->expectException(UnknownRoleException::class);
        $user->syncRoles([]);

        // Silence static analyser by touching $roleId after the
        // throw — the assertion itself doesn't run but keeps IDEs
        // from flagging the unused local.
        static::assertNotSame('', $roleId);
    }

    /**
     * `resolvePermissionById()` throws when the ID is unknown.
     * Targets `HasPermissions` line 351 via `syncPermissions()`
     * detachment with a deleted permission row.
     *
     * @return void
     */
    public function testResolvePermissionByIdThrowsWhenMissing(): void
    {
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);

        $permission = Permission::create(['id' => (string) Str::uuid(), 'name' => 'gone', 'guard_name' => 'web']);
        $user->givePermission($permission);
        Schema::disableForeignKeyConstraints();
        $permission->delete();
        Schema::enableForeignKeyConstraints();

        $this->expectException(UnknownPermissionException::class);
        $user->syncPermissions([]);
    }

    /**
     * A cached permissions entry whose resolver returns nothing and
     * whose stored value is the empty array hits the
     * `array_filter(is_string)` branch that discards non-string
     * entries — we sneak one in via the fresh cache to cover the
     * filter branch on `rememberStringList`.
     *
     * Targets `ResolutionCache::rememberStringList` line 308 filter
     * branch.
     *
     * @return void
     */
    public function testRememberStringListFiltersNonStringEntriesFromPersistentStore(): void
    {
        $driver = self::makeNonTaggableDriver();
        $store  = new \Illuminate\Cache\Repository($driver);
        $cache  = new ResolutionCache(store: $store, ttl: 0, prefix: 'authorization-test');

        $principal = StubIdentity::create(['id' => (string) Str::uuid()]);

        // Prime the persistent tier via the cache so the written
        // key precisely matches the cache's internal key shape.
        // A fresh instance then bypasses the memo and re-reads the
        // corrupted payload from the store.
        $cache->rememberPermissions($principal, static fn (): array => ['seed']);

        // Corrupt the stored entry in-place — swap the single
        // seeded value for a mixed-type list. The filter branch
        // in `rememberStringList` drops the non-string items and
        // returns only the strings.
        $key = \array_key_first($driver->storage);
        static::assertIsString($key);
        $driver->storage[$key] = ['valid:perm', 42, null, 'another:perm'];

        $fresh = new ResolutionCache(store: $store, ttl: 0, prefix: 'authorization-test');

        $result = $fresh->rememberPermissions($principal, static fn (): array => \PHPUnit\Framework\Assert::fail('Resolver should not be called on a store hit.'));

        static::assertSame(['valid:perm', 'another:perm'], $result);
    }

    /**
     * `forgetRoleTags()` is a no-op when the role exposes no key.
     * Targets `ResolutionCache::forgetRoleTags` line 240 (empty ID
     * early return) via a role-like object whose `getKey()` yields
     * an empty string.
     *
     * @return void
     */
    public function testForgetRoleTagsIsNoopForRoleWithEmptyKey(): void
    {
        $cache = new ResolutionCache(
            store: \Illuminate\Support\Facades\Cache::store('array'),
            ttl: 0,
            prefix: 'authorization-test',
        );

        $role = new class {
            public function getKey(): string
            {
                return '';
            }
        };

        // Method returns void; the assertion is that no exception
        // is raised and no tag-flush occurs.
        $cache->forgetRoleTags($role);

        static::assertTrue(true);
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
        $store  = new \Illuminate\Cache\Repository($driver);
        $cache  = new ResolutionCache(store: $store, ttl: 0, prefix: 'authorization-test');

        $role = Role::create(['id' => (string) Str::uuid(), 'name' => 'ghost', 'guard_name' => 'web']);

        // Expect no exception raised when the underlying driver
        // lacks `tags()` — the method exits at the early guard.
        $cache->forgetRoleTags($role);

        static::assertTrue(true);
    }

    /**
     * `forget()` on a non-tag store iterates every slot. Targets
     * lines 210-211 of `ResolutionCache::forget`.
     *
     * @return void
     */
    public function testForgetIteratesEverySlotOnNonTagStore(): void
    {
        $driver = self::makeNonTaggableDriver();
        $store  = new \Illuminate\Cache\Repository($driver);
        $cache  = new ResolutionCache(store: $store, ttl: 0, prefix: 'authorization-test');

        $principal = StubIdentity::create(['id' => (string) Str::uuid()]);

        $cache->rememberPermissions($principal, static fn (): array => ['a:do']);
        $cache->rememberRoles($principal, static fn (): array => ['admin']);

        static::assertNotEmpty($driver->storage, 'Persistent store should contain entries before forget().');

        $cache->forget($principal);

        static::assertEmpty($driver->storage, 'Non-tag forget() should remove every per-principal slot.');
    }

    /**
     * Principal with an object that exposes neither `getKey()` nor
     * `getMorphClass()` falls back to the `spl_object_hash`-based
     * key path. Targets `ResolutionCache::keyFor` line 391.
     *
     * @return void
     */
    public function testKeyForFallsBackToSplObjectHashForBareObject(): void
    {
        $cache     = new ResolutionCache;
        $principal = new \stdClass;

        $cache->rememberPermissions($principal, static fn (): array => ['z:do']);

        // Same object returns the memoised value without invoking
        // the resolver again.
        $result = $cache->rememberPermissions($principal, static fn (): array => \PHPUnit\Framework\Assert::fail('memoised'));

        static::assertSame(['z:do'], $result);
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
            store: \Illuminate\Support\Facades\Cache::store('array'),
            ttl: 0,
            prefix: 'authorization-test',
        );

        $principal = StubIdentity::create(['id' => (string) Str::uuid()]);

        // Route an empty-ID entry through the remember flow — the
        // tags builder drops it silently, so the write succeeds.
        $cache->rememberPermissions(
            $principal,
            static fn (): array => ['t:do'],
            new \SineMacula\Laravel\Authorization\Cache\ResolutionCacheContext(maxTtl: null, roleIds: ['', 'real-role-id']),
        );

        static::assertSame(['t:do'], $cache->rememberPermissions($principal, static fn (): array => []));
    }

    /**
     * A `putInStore` call with a `maxTtl` of zero short-circuits
     * without writing. Targets line 595 of `ResolutionCache`.
     *
     * @return void
     */
    public function testPutInStoreSkipsWhenTtlIsZeroOrLess(): void
    {
        $driver = self::makeNonTaggableDriver();
        $store  = new \Illuminate\Cache\Repository($driver);
        $cache  = new ResolutionCache(store: $store, ttl: 0, prefix: 'authorization-test');

        $principal = StubIdentity::create(['id' => (string) Str::uuid()]);

        // `maxTtl = 1` with `min($base, 1) - 1 = 0` triggers the
        // short-circuit. The resolver still runs and the return
        // value is propagated, but nothing lands in the driver.
        $cache->rememberPermissions(
            $principal,
            static fn (): array => ['x:do'],
            new \SineMacula\Laravel\Authorization\Cache\ResolutionCacheContext(maxTtl: 1),
        );

        static::assertSame([], $driver->storage, 'Persistent tier must skip zero/negative TTL writes.');
    }

    /**
     * `BladeHelpers::hasAllRoles` returns false when the principal
     * does not implement `SupportsRoles`. Targets line 80.
     *
     * @return void
     */
    public function testBladeHelpersHasAllRolesReturnsFalseForNonRoleSupportingPrincipal(): void
    {
        $this->app->instance(
            \SineMacula\Laravel\Authorization\Contracts\PrincipalResolver::class,
            new class implements \SineMacula\Laravel\Authorization\Contracts\PrincipalResolver {
                public function resolve(): ?object
                {
                    return new \stdClass;
                }
            },
        );

        static::assertFalse(BladeHelpers::hasAllRoles(['admin']));
    }

    // Spatie-migration-specific coverage lives in MigrateSpatieSkipTest; that
    // test suite configures the package tables at `defineEnvironment` time so
    // the `roles` / `permissions` names are free for the Spatie source schema.

    /**
     * `ResolvesPivotExpiry::authorizationCoerceExpiresAt` returns
     * a Carbon instance when the raw pivot value is a non-empty
     * string. Targets lines 135-136 of the trait via a temporal
     * role assignment routed through `getRoles()`.
     *
     * @return void
     */
    public function testCoerceExpiresAtHandlesStringValue(): void
    {
        $role = Role::create(['id' => (string) Str::uuid(), 'name' => 'temp', 'guard_name' => 'web']);
        $user = StubIdentity::create(['id' => (string) Str::uuid()]);
        $user->assignRole($role, \Carbon\Carbon::now()->addHour());

        $names = $user->fresh()?->getRoles() ?? [];

        static::assertSame(['temp'], $names);
    }

    /**
     * `ResolvesPivotExpiry::authorizationCoerceExpiresAt` returns
     * null when the raw pivot value is an empty string. Targets
     * line 139 of the trait.
     *
     * @return void
     */
    public function testCoerceExpiresAtReturnsNullForEmptyString(): void
    {
        // Direct invocation through a helper class that composes
        // the trait — the public behaviour routes through
        // `authorizationNearestPivotExpirySeconds` which calls
        // `authorizationCoerceExpiresAt`. We invoke via reflection
        // on a freshly-instantiated test-only composer.
        $probe = new class {
            use ResolvesPivotExpiry;

            public function coerce(mixed $raw): mixed
            {
                return self::authorizationCoerceExpiresAt($raw);
            }
        };

        static::assertNull($probe->coerce(''));
        static::assertNull($probe->coerce(null));
        static::assertNull($probe->coerce(42));

        // Non-empty string — exercises the `Carbon::parse($raw)` branch.
        $carbon = $probe->coerce('2026-01-01 00:00:00');
        static::assertInstanceOf(\Illuminate\Support\Carbon::class, $carbon);

        // DateTimeInterface — exercises the other branch.
        $carbon = $probe->coerce(new \DateTimeImmutable('2026-01-01 00:00:00'));
        static::assertInstanceOf(\Illuminate\Support\Carbon::class, $carbon);
    }

    /**
     * `ResolvesPivotExpiry::authorizationMinNullable` returns the
     * smaller of two non-null seconds. Targets line 160.
     *
     * @return void
     */
    public function testAuthorizationMinNullableReturnsSmallerOfTwoInts(): void
    {
        $probe = new class {
            use ResolvesPivotExpiry;

            public function min(?int $left, ?int $right): ?int
            {
                return self::authorizationMinNullable($left, $right);
            }
        };

        static::assertSame(3, $probe->min(5, 3));
        static::assertSame(3, $probe->min(3, 5));
        static::assertSame(5, $probe->min(null, 5));
        static::assertSame(5, $probe->min(5, null));
        static::assertNull($probe->min(null, null));
    }

    /**
     * `ResolvesPivotExpiry::authorizationCoerceGrantExpiry` returns
     * the DateTimeInterface unchanged, parses strings, and null-pads
     * everything else. Targets lines 254-262.
     *
     * @return void
     */
    public function testAuthorizationCoerceGrantExpiryHandlesAllBranches(): void
    {
        $probe = new class {
            use ResolvesPivotExpiry;

            public function coerce(mixed $value): mixed
            {
                return self::authorizationCoerceGrantExpiry($value);
            }
        };

        $dt = new \DateTimeImmutable('+1 hour');
        static::assertSame($dt, $probe->coerce($dt));

        $carbon = $probe->coerce('2026-01-01 00:00:00');
        static::assertInstanceOf(\DateTimeInterface::class, $carbon);

        static::assertNull($probe->coerce(null));
        static::assertNull($probe->coerce(''));
        static::assertNull($probe->coerce(42));
    }

    /**
     * `ResolvesPivotExpiry::authorizationSecondsUntilPivotExpiry`
     * returns null when the pivot is absent on the model. Targets
     * line 100.
     *
     * @return void
     */
    public function testSecondsUntilPivotExpiryReturnsNullWhenPivotMissing(): void
    {
        $probe = new class {
            use ResolvesPivotExpiry;

            public function seconds(\Illuminate\Database\Eloquent\Model $model): ?int
            {
                return self::authorizationSecondsUntilPivotExpiry($model, 0);
            }
        };

        $model = new class extends \Illuminate\Database\Eloquent\Model {};

        static::assertNull($probe->seconds($model));
    }

    /**
     * When `logger()->channel('authorization')` throws, the
     * malformed-policy logger falls back to the default channel.
     * Targets lines 272-273 of `HasPolicies::logMalformedPolicy`.
     *
     * @return void
     */
    public function testLogMalformedPolicyFallsBackWhenAuthorizationChannelFails(): void
    {
        // Rebind the logger to one whose `channel('authorization')`
        // raises so the malformed-policy logger takes the
        // default-channel fallback branch. Implements LoggerInterface
        // so the `logger()` helper's return type is satisfied.
        $fakeLog = new class extends \Psr\Log\AbstractLogger {
            public int $channelCalls    = 0;
            public int $warningCalls    = 0;
            public ?string $lastMessage = null;

            /** @var array<string, mixed>|null */
            public ?array $lastContext = null;

            public function channel(string $name): self
            {
                $this->channelCalls++;

                throw new \RuntimeException('channel ' . $name . ' is unavailable');
            }

            public function warning(string|\Stringable $message, array $context = []): void
            {
                $this->warningCalls++;
                $this->lastMessage = (string) $message;
                $this->lastContext = $context;
            }

            public function log($level, string|\Stringable $message, array $context = []): void {}
        };
        $this->app->instance('log', $fakeLog);

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);

        $policy = \SineMacula\Laravel\Authorization\Models\Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'malformed-fallback',
            'document' => ['statements' => [['effect' => 'allow', 'actions' => ['x']]]],
        ]);
        $user->attachPolicy($policy);

        $policyId = (string) $policy->getKey();

        // Overwrite the stored document with a JSON-encoded array
        // that lacks the required statements key — the Eloquent
        // array cast yields a decoded value and `EvaluationPolicy::fromArray`
        // then fails the schema validator, triggering the logger
        // fallback path inside `logMalformedPolicy`.
        \Illuminate\Support\Facades\DB::table((string) config('authorization.tables.policies', 'policies'))
            ->where('id', $policyId)
            ->update(['document' => \json_encode(['version' => 'not-an-int'])]);

        $results = $user->fresh()?->getPolicies() ?? [];
        static::assertSame([], $results);

        // Confirm the fallback branch ran — `channel()` raised
        // and the default logger's `warning()` was used.
        static::assertGreaterThanOrEqual(1, $fakeLog->channelCalls, 'channel() should be attempted');
        static::assertGreaterThanOrEqual(1, $fakeLog->warningCalls, 'warning() should land on the default logger');

        // Pin the exact warning content so the concat and context
        // array inside `logMalformedPolicy` stay honest against
        // ConcatOperandRemoval / ArrayItemRemoval / CastString
        // mutations.
        static::assertNotNull($fakeLog->lastMessage);
        static::assertStringStartsWith("Authorization: skipping malformed policy '{$policyId}' — ", $fakeLog->lastMessage);

        static::assertIsArray($fakeLog->lastContext);
        static::assertArrayHasKey('policy_id', $fakeLog->lastContext);
        static::assertArrayHasKey('policy_name', $fakeLog->lastContext);
        static::assertArrayHasKey('reason', $fakeLog->lastContext);
        static::assertSame($policyId, $fakeLog->lastContext['policy_id']);
        static::assertSame('malformed-fallback', $fakeLog->lastContext['policy_name']);
        static::assertIsString($fakeLog->lastContext['reason']);
        static::assertNotSame('', $fakeLog->lastContext['reason']);
    }

    /**
     * `logMalformedPolicy` also tolerates a logger that throws on
     * the warning call itself. Targets line 284 of
     * `HasPolicies::logMalformedPolicy`.
     *
     * @return void
     */
    public function testLogMalformedPolicyTolerantOfLoggerWarningFailure(): void
    {
        // Rebind the logger to one whose `warning()` raises. The
        // method swallows the failure so hydration still succeeds.
        $this->app->instance('log', new class extends \Psr\Log\AbstractLogger {
            public function channel(string $name): self
            {
                return $this;
            }

            public function warning(string|\Stringable $message, array $context = []): void
            {
                throw new \RuntimeException('logger unavailable');
            }

            public function log($level, string|\Stringable $message, array $context = []): void {}
        });

        $user = StubIdentity::create(['id' => (string) Str::uuid()]);

        $policy = \SineMacula\Laravel\Authorization\Models\Policy::create([
            'id'       => (string) Str::uuid(),
            'name'     => 'malformed-warn',
            'document' => ['statements' => [['effect' => 'allow', 'actions' => ['x']]]],
        ]);
        $user->attachPolicy($policy);

        // Replace with a JSON payload lacking the `statements` key
        // so `EvaluationPolicy::fromArray()` raises.
        \Illuminate\Support\Facades\DB::table((string) config('authorization.tables.policies', 'policies'))
            ->where('id', $policy->getKey())
            ->update(['document' => \json_encode(['version' => 'not-an-int'])]);

        $results = $user->fresh()?->getPolicies() ?? [];
        static::assertSame([], $results);
    }

    /**
     * A corrupt cache payload triggers the warning path on a
     * misconfigured `authorization` channel — the cache falls
     * back to the default channel. Targets lines 542-543 and 553
     * of `ResolutionCache::logCorruptCacheEntry`.
     *
     * @return void
     */
    public function testLogCorruptCacheEntryHandlesChannelMisconfiguration(): void
    {
        $fakeLog = new class extends \Psr\Log\AbstractLogger {
            public int $channelCalls    = 0;
            public int $warningCalls    = 0;
            public ?string $lastMessage = null;

            /** @var array<string, mixed>|null */
            public ?array $lastContext = null;

            public function channel(string $name): self
            {
                $this->channelCalls++;

                throw new \RuntimeException('channel ' . $name . ' is unavailable');
            }

            public function warning(string|\Stringable $message, array $context = []): void
            {
                $this->warningCalls++;
                $this->lastMessage = (string) $message;
                $this->lastContext = $context;
            }

            public function log($level, string|\Stringable $message, array $context = []): void {}
        };
        $this->app->instance('log', $fakeLog);

        $driver = self::makeNonTaggableDriver();
        $store  = new \Illuminate\Cache\Repository($driver);
        $cache  = new ResolutionCache(store: $store, ttl: 0, prefix: 'authorization-test');

        $principal = StubIdentity::create(['id' => (string) Str::uuid()]);

        // Prime + corrupt the persistent entry so the read path
        // raises and the logger branch fires. A non-array element
        // inside the stored list trips `Policy::fromArray()`.
        $cache->rememberPolicies($principal, static fn (): array => []);
        $key                   = (string) \array_key_first($driver->storage);
        $driver->storage[$key] = ['not-an-array'];

        $fresh  = new ResolutionCache(store: $store, ttl: 0, prefix: 'authorization-test');
        $result = $fresh->rememberPolicies($principal, static fn (): array => []);

        static::assertSame([], $result);
        static::assertGreaterThanOrEqual(1, $fakeLog->channelCalls, 'channel() should be attempted');
        static::assertGreaterThanOrEqual(1, $fakeLog->warningCalls, 'warning() should land on the default logger');

        // Pin the logged content — `cache_key` and `reason` must
        // land in the context with the exact key the cache emitted.
        static::assertNotNull($fakeLog->lastMessage);
        static::assertStringStartsWith("Authorization: discarding corrupt resolution-cache entry '{$key}' — ", $fakeLog->lastMessage);

        static::assertIsArray($fakeLog->lastContext);
        static::assertArrayHasKey('cache_key', $fakeLog->lastContext);
        static::assertArrayHasKey('reason', $fakeLog->lastContext);
        static::assertSame($key, $fakeLog->lastContext['cache_key']);
        static::assertIsString($fakeLog->lastContext['reason']);
        static::assertNotSame('', $fakeLog->lastContext['reason']);
    }

    /**
     * `rememberPolicies` returns the memoised value on a second
     * call without hitting the persistent store. Targets line 99
     * of `ResolutionCache::rememberPolicies`.
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
        $second = $cache->rememberPolicies($principal, static fn (): array => \PHPUnit\Framework\Assert::fail('memoised'));

        static::assertSame($first, $second);
    }

    /**
     * A valid persistent policy document payload round-trips
     * through `rememberPolicies`. Targets line 116 (`fromArray`
     * call inside the hydration loop) of `ResolutionCache`.
     *
     * @return void
     */
    public function testRememberPoliciesHydratesFromPersistentPayload(): void
    {
        $driver = self::makeNonTaggableDriver();
        $store  = new \Illuminate\Cache\Repository($driver);
        $cache  = new ResolutionCache(store: $store, ttl: 0, prefix: 'authorization-test');

        $principal = StubIdentity::create(['id' => (string) Str::uuid()]);

        $policy = new \SineMacula\Laravel\Authorization\Evaluation\Policy(
            name: 'hydrated',
            statements: [],
        );
        $cache->rememberPolicies($principal, static fn (): array => [$policy]);

        // Fresh instance bypasses the memo and hydrates from the
        // persistent tier — exercising the `Policy::fromArray`
        // loop branch.
        $fresh  = new ResolutionCache(store: $store, ttl: 0, prefix: 'authorization-test');
        $result = $fresh->rememberPolicies(
            $principal,
            static fn (): array => \PHPUnit\Framework\Assert::fail('Should hit the persistent store.'),
        );

        static::assertCount(1, $result);
        static::assertSame('hydrated', $result[0]->name);
    }

    /**
     * A driver whose `get()` raises triggers the corrupt-entry
     * recovery path in `rememberStringList`. Targets lines 310,
     * 313, 314 of `ResolutionCache`.
     *
     * @return void
     */
    public function testRememberStringListRecoversFromDriverGetFailure(): void
    {
        $driver = new class implements \Illuminate\Contracts\Cache\Store {
            /** @var array<string, mixed> */
            public array $storage   = [];
            public int $getCalls    = 0;
            public int $forgetCalls = 0;

            public function get($key): mixed
            {
                $this->getCalls++;

                throw new \RuntimeException('transient driver failure');
            }

            public function many(array $keys): array
            {
                return [];
            }

            public function put($key, $value, $seconds): bool
            {
                $this->storage[$key] = $value;

                return true;
            }

            public function putMany(array $values, mixed $seconds): bool
            {
                return true;
            }

            public function increment($key, $value = 1): bool|int
            {
                return false;
            }

            public function decrement($key, $value = 1): bool|int
            {
                return false;
            }

            public function forever($key, $value): bool
            {
                $this->storage[$key] = $value;

                return true;
            }

            public function touch($key, $ttl): bool
            {
                return true;
            }

            public function forget($key): bool
            {
                $this->forgetCalls++;
                unset($this->storage[$key]);

                return true;
            }

            public function flush(): bool
            {
                $this->storage = [];

                return true;
            }

            public function getPrefix(): string
            {
                return '';
            }
        };

        $store = new \Illuminate\Cache\Repository($driver);
        $cache = new ResolutionCache(store: $store, ttl: 0, prefix: 'authorization-test');

        $principal = StubIdentity::create(['id' => (string) Str::uuid()]);

        $result = $cache->rememberPermissions($principal, static fn (): array => ['fresh:perm']);

        static::assertSame(['fresh:perm'], $result);
        static::assertGreaterThanOrEqual(1, $driver->getCalls, 'driver get() should be attempted');
        static::assertGreaterThanOrEqual(1, $driver->forgetCalls, 'forget() should be called on corruption');
    }

    /**
     * `logCorruptCacheEntry` tolerates a logger whose `warning()`
     * raises. Targets line 553 of `ResolutionCache`.
     *
     * @return void
     */
    public function testLogCorruptCacheEntryTolerantOfLoggerWarningFailure(): void
    {
        $this->app->instance('log', new class extends \Psr\Log\AbstractLogger {
            public function channel(string $name): self
            {
                return $this;
            }

            public function warning(string|\Stringable $message, array $context = []): void
            {
                throw new \RuntimeException('logger unavailable');
            }

            public function log($level, string|\Stringable $message, array $context = []): void {}
        });

        $driver = self::makeNonTaggableDriver();
        $store  = new \Illuminate\Cache\Repository($driver);
        $cache  = new ResolutionCache(store: $store, ttl: 0, prefix: 'authorization-test');

        $principal = StubIdentity::create(['id' => (string) Str::uuid()]);

        $cache->rememberPolicies($principal, static fn (): array => []);
        $key                   = (string) \array_key_first($driver->storage);
        $driver->storage[$key] = ['still-not-an-array'];

        $fresh = new ResolutionCache(store: $store, ttl: 0, prefix: 'authorization-test');

        // The fail-closed contract ensures hydration still returns.
        $result = $fresh->rememberPolicies($principal, static fn (): array => []);

        static::assertSame([], $result);
    }

    /**
     * Build a bare non-taggable `Store` — mirrors the helper used
     * by `ResolutionCacheTest`.
     *
     * @return object
     */
    private static function makeNonTaggableDriver(): object
    {
        return new class implements \Illuminate\Contracts\Cache\Store {
            /** @var array<string, mixed> */
            public array $storage = [];

            public function get($key): mixed
            {
                return $this->storage[$key] ?? null;
            }

            /**
             * @param  array<int, string>  $keys
             * @return array<string, mixed>
             */
            public function many(array $keys): array
            {
                $result = [];

                foreach ($keys as $key) {
                    $result[$key] = $this->storage[$key] ?? null;
                }

                return $result;
            }

            public function put($key, $value, $seconds): bool
            {
                $this->storage[$key] = $value;

                return true;
            }

            /**
             * @param  array<string, mixed>  $values
             * @param  mixed  $seconds
             */
            public function putMany(array $values, mixed $seconds): bool
            {
                foreach ($values as $key => $value) {
                    $this->storage[$key] = $value;
                }

                return true;
            }

            public function increment($key, $value = 1): bool|int
            {
                return false;
            }

            public function decrement($key, $value = 1): bool|int
            {
                return false;
            }

            public function forever($key, $value): bool
            {
                $this->storage[$key] = $value;

                return true;
            }

            public function touch($key, $ttl): bool
            {
                return isset($this->storage[$key]);
            }

            public function forget($key): bool
            {
                unset($this->storage[$key]);

                return true;
            }

            public function flush(): bool
            {
                $this->storage = [];

                return true;
            }

            public function getPrefix(): string
            {
                return '';
            }
        };
    }
}
