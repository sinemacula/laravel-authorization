<?php

declare(strict_types = 1);

namespace Tests\Feature\Cache;

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Cache;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Cache\Invalidation;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Cache\VersionedStore;
use SineMacula\Laravel\Authorization\Events\Identity\RoleAssigned;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\GrantPruner;
use SineMacula\Laravel\Authorization\Services\PermissionService;
use SineMacula\Laravel\Authorization\Services\PolicyService;
use SineMacula\Laravel\Authorization\Services\RoleService;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for which versions each write bumps, and for every change
 * taking effect on the next request with a persistent store, however the
 * entries it invalidates were built.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Invalidation::class)]
final class InvalidationTest extends TestCase
{
    /**
     * Keep entries in the array store.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        config(['authorization.cache.store' => 'array']);

        $this->nextRequest();
    }

    /**
     * A grant, an expiry change and a revocation each bump the grantee and
     * nothing else.
     *
     * @return void
     */
    public function testGrantsBumpTheGrantee(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);
        $role = Role::create(['name' => 'editor']);

        self::assertSame([$this->versions()->granteeKey($user)], $this->bumpedBy(static fn () => $user->assignRole($role), $user, $role));
        self::assertSame([$this->versions()->granteeKey($user)], $this->bumpedBy(static fn () => $user->assignRole($role, now()->addHour()), $user, $role));
        self::assertSame([$this->versions()->granteeKey($user)], $this->bumpedBy(static fn () => $user->revokeRole($role), $user, $role));
    }

    /**
     * The events of one write bump each version once, in the order the events
     * name them.
     *
     * @return void
     */
    public function testEachVersionIsBumpedOnce(): void
    {
        $user   = new Reference('user', 'user-1');
        $events = [
            new RoleAssigned(Operation::begin(), $user, new Reference('role', 'role-1'), 'editor', GrantScope::platform(), null),
            new RoleAssigned(Operation::begin(), new Reference('user', 'user-2'), new Reference('role', 'role-1'), 'editor', GrantScope::platform(), null),
            new RoleAssigned(Operation::begin(), $user, new Reference('role', 'role-2'), 'author', GrantScope::platform(), null),
        ];

        self::assertSame(
            ['authorization:version:grantee:user:user-1', 'authorization:version:grantee:user:user-2'],
            Invalidation::keys($this->versions(), $events),
        );
    }

    /**
     * A change to a role's permissions, its parent or its name, and its
     * deletion, each bump the role; creating one bumps nothing.
     *
     * @return void
     */
    public function testRoleChangesBumpTheRole(): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $roles  = $this->app?->make(RoleService::class);
        $parent = Role::create(['name' => 'reader']);
        $role   = Role::create(['name' => 'editor']);
        $key    = [$this->versions()->roleKey($role->id)];

        self::assertNotNull($roles);
        self::assertSame([], $this->bumpedBy(static fn () => Role::create(['name' => 'other']), $user, $role));
        self::assertSame($key, $this->bumpedBy(static fn () => $roles->grantPermission($role, Permission::create(['name' => 'posts:edit'])), $user, $role));
        self::assertSame($key, $this->bumpedBy(static fn () => $roles->grantPermission($role, 'posts:edit', Carbon::parse('2000-01-01 00:00:00')), $user, $role));
        self::assertSame($key, $this->bumpedBy(static fn () => app(GrantPruner::class)->prune(1000), $user, $role));
        self::assertSame($key, $this->bumpedBy(static fn () => $roles->grantPermission($role, Permission::create(['name' => 'posts:read'])), $user, $role));
        self::assertSame($key, $this->bumpedBy(static fn () => $roles->revokePermission($role, 'posts:read'), $user, $role));
        self::assertSame($key, $this->bumpedBy(static fn () => $roles->setParent($role, $parent), $user, $role));
        self::assertSame($key, $this->bumpedBy(static fn () => $roles->rename($role, 'author'), $user, $role));
        self::assertSame($key, $this->bumpedBy(static fn () => $roles->delete($role), $user, $role));
    }

    /**
     * A change to a policy and its deletion each bump the policy.
     *
     * @return void
     */
    public function testPolicyChangesBumpThePolicy(): void
    {
        $user     = StubIdentity::create(['id' => 'user-1']);
        $role     = Role::create(['name' => 'editor']);
        $policies = $this->app?->make(PolicyService::class);
        $policy   = Policy::create(['name' => 'readers', 'document' => ['version' => 1, 'statements' => []]]);
        $key      = [$this->versions()->policyKey($policy->id)];

        self::assertNotNull($policies);
        $deny = ['version' => 1, 'statements' => [['effect' => 'deny', 'actions' => ['*']]]];

        self::assertSame($key, $this->bumpedBy(static fn () => $policies->rewrite($policy, $deny), $user, $role, $policy));
        self::assertSame($key, $this->bumpedBy(static fn () => $policies->delete($policy), $user, $role, $policy));
    }

    /**
     * Renaming a permission or deleting it bumps the roles and grantees that
     * hold it; describing it bumps nothing.
     *
     * @return void
     */
    public function testPermissionChangesBumpItsHolders(): void
    {
        $user        = StubIdentity::create(['id' => 'user-1']);
        $role        = Role::create(['name' => 'editor']);
        $permissions = $this->app?->make(PermissionService::class);
        $permission  = Permission::create(['name' => 'posts:edit']);

        $role->givePermission($permission);
        $user->givePermission($permission);

        $holders = [$this->versions()->roleKey($role->id), $this->versions()->granteeKey($user)];

        self::assertNotNull($permissions);
        self::assertSame([], $this->bumpedBy(static fn () => $permissions->describe($permission, 'Edit posts'), $user, $role));
        self::assertSame($holders, $this->bumpedBy(static fn () => $permissions->rename($permission, 'posts:write'), $user, $role));
        self::assertSame($holders, $this->bumpedBy(static fn () => $permissions->delete($permission), $user, $role));
    }

    /**
     * Moving a role under a parent gives its holders the parent's permissions
     * on the next request (#48).
     *
     * @return void
     */
    public function testAReparentedRoleTakesEffectOnTheNextRequest(): void
    {
        $publisher = Role::create(['name' => 'publisher']);
        $editor    = Role::create(['name' => 'editor']);
        $user      = StubIdentity::create(['id' => 'user-1']);

        $publisher->givePermission(Permission::create(['name' => 'posts:publish']));
        $user->assignRole($editor);

        self::assertFalse($user->hasPermission('posts:publish'));

        $this->nextRequest();
        $this->app?->make(RoleService::class)->setParent($editor, $publisher);
        $this->nextRequest();

        self::assertTrue($this->fresh($user)->hasPermission('posts:publish'));
    }

    /**
     * Changing a policy's document reaches its holders on the next request
     * (#48).
     *
     * @return void
     */
    public function testAnEditedPolicyTakesEffectOnTheNextRequest(): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $policy = Policy::create(['name' => 'readers', 'document' => ['version' => 1, 'statements' => [['effect' => 'allow', 'actions' => ['invoices:read']]]]]);

        $user->attachPolicy($policy);

        self::assertSame('allow', $user->getPolicies()[0]->statements[0]->effect->value);

        $this->nextRequest();
        $this->app?->make(PolicyService::class)->rewrite($policy, ['version' => 1, 'statements' => [['effect' => 'deny', 'actions' => ['invoices:read']]]]);
        $this->nextRequest();

        self::assertSame('deny', $this->fresh($user)->getPolicies()[0]->statements[0]->effect->value);
    }

    /**
     * A renamed permission and a deleted role reach their holders on the next
     * request (#48).
     *
     * @return void
     */
    public function testRenamesAndDeletesTakeEffectOnTheNextRequest(): void
    {
        $role = Role::create(['name' => 'editor']);
        $user = StubIdentity::create(['id' => 'user-1']);

        $role->givePermission(Permission::create(['name' => 'posts:edit']));
        $user->assignRole($role);

        self::assertSame(['posts:edit'], $user->getPermissions());
        self::assertSame(['editor'], $user->getRoles());

        $this->nextRequest();
        $this->app?->make(PermissionService::class)->rename('posts:edit', 'posts:write');
        $this->nextRequest();

        self::assertSame(['posts:write'], $this->fresh($user)->getPermissions());

        $this->app?->make(RoleService::class)->delete($role);
        $this->nextRequest();

        self::assertSame([], $this->fresh($user)->getPermissions());
        self::assertSame([], $this->fresh($user)->getRoles());
    }

    /**
     * Return the version keys among the user's, the role's and the policy's
     * whose tokens the write changed.
     *
     * @param  \Closure(): mixed  $write
     * @param  \Tests\Feature\Stubs\StubIdentity  $user
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @param  \SineMacula\Laravel\Authorization\Models\Policy|null  $policy
     * @return list<string>
     */
    private function bumpedBy(\Closure $write, StubIdentity $user, Role $role, ?Policy $policy = null): array
    {
        $keys = [$this->versions()->roleKey($role->id), $this->versions()->granteeKey($user)];

        if ($policy !== null) {
            $keys[] = $this->versions()->policyKey($policy->id);
        }

        $before = $this->versions()->tokens($keys);

        $write();

        $after = $this->versions()->tokens($keys);

        return \array_values(\array_filter($keys, static fn (string $key): bool => ($before[$key] ?? null) !== ($after[$key] ?? null)));
    }

    /**
     * Return the versions in the array store under the package's prefix.
     *
     * @return \SineMacula\Laravel\Authorization\Cache\VersionedStore
     */
    private function versions(): VersionedStore
    {
        return new VersionedStore(Cache::store('array'), 'authorization');
    }

    /**
     * Start a new request: the memo of the last one is gone, the store stays.
     *
     * @return void
     */
    private function nextRequest(): void
    {
        $this->app?->forgetInstance(ResolutionCache::class);
    }

    /**
     * Read the identity afresh, as the next request does.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $user
     * @return \Tests\Feature\Stubs\StubIdentity
     */
    private function fresh(StubIdentity $user): StubIdentity
    {
        return StubIdentity::query()->whereKey($user->getKey())->firstOrFail();
    }
}
