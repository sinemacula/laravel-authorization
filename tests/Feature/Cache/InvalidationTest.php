<?php

declare(strict_types = 1);

namespace Tests\Feature\Cache;

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Cache;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Cache\Invalidation;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Cache\VersionedStore;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Events\Identity\RoleAssigned;
use SineMacula\Laravel\Authorization\Events\Resource\PolicyAttached as ResourcePolicyAttached;
use SineMacula\Laravel\Authorization\Events\Resource\PolicyDetached as ResourcePolicyDetached;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Resolvers\BoundaryResolver;
use SineMacula\Laravel\Authorization\Resolvers\GuardrailResolver;
use SineMacula\Laravel\Authorization\Services\BoundaryService;
use SineMacula\Laravel\Authorization\Services\GrantPruner;
use SineMacula\Laravel\Authorization\Services\GuardrailService;
use SineMacula\Laravel\Authorization\Services\PermissionService;
use SineMacula\Laravel\Authorization\Services\PolicyService;
use SineMacula\Laravel\Authorization\Services\RoleService;
use SineMacula\Laravel\Authorization\Support\GrantScope;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
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
     * A policy attached to, re-dated on or detached from a role bumps the role
     * as a grantee and the version every role's policy attachments share, and
     * nothing else; one attached to an identity leaves the shared version
     * alone.
     *
     * @return void
     */
    public function testRolePolicyChangesBumpTheSharedVersion(): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $role   = Role::create(['name' => 'editor']);
        $policy = Policy::create(['name' => 'editors', 'document' => ['version' => 1, 'statements' => []]]);
        $both   = [$this->versions()->granteeKey($role), $this->versions()->rolePoliciesKey()];

        self::assertSame($both, $this->bumpedBy(static fn () => $role->attachPolicy($policy), $user, $role, $policy, true));
        self::assertSame($both, $this->bumpedBy(static fn () => $role->attachPolicy($policy, now()->addHour()), $user, $role, $policy, true));
        self::assertSame($both, $this->bumpedBy(static fn () => $role->detachPolicy($policy), $user, $role, $policy, true));
        self::assertSame([$this->versions()->granteeKey($user)], $this->bumpedBy(static fn () => $user->attachPolicy($policy), $user, $role, $policy, true));
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
     * A change to a policy and its deletion each bump the policy, and the
     * versions every resource policy entry, every boundary entry and every
     * guardrail entry share.
     *
     * @return void
     */
    public function testPolicyChangesBumpThePolicy(): void
    {
        $user     = StubIdentity::create(['id' => 'user-1']);
        $role     = Role::create(['name' => 'editor']);
        $policies = $this->app?->make(PolicyService::class);
        $policy   = Policy::create(['name' => 'readers', 'document' => ['version' => 1, 'statements' => []]]);
        $key      = [$this->versions()->policyKey($policy->id), $this->versions()->resourcePoliciesKey(), $this->versions()->boundariesKey(), $this->versions()->guardrailsKey()];

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
     * A policy attached to or detached from a role reaches every holder of the
     * role, and of the roles below it, on the next request.
     *
     * @return void
     */
    public function testARolePolicyAttachedOrDetachedTakesEffectOnTheNextRequest(): void
    {
        $staff  = Role::create(['name' => 'staff']);
        $editor = Role::create(['name' => 'editor', 'parent_id' => $staff->id]);
        $user   = StubIdentity::create(['id' => 'user-1']);
        $policy = Policy::create(['name' => 'staff', 'document' => ['version' => 1, 'statements' => []]]);

        $user->assignRole($editor);

        self::assertSame([], self::names($user->getPolicies()));

        $this->nextRequest();
        $staff->attachPolicy($policy);
        $this->nextRequest();

        self::assertSame(['staff'], self::names($this->fresh($user)->getPolicies()));

        $this->nextRequest();
        $staff->detachPolicy($policy);
        $this->nextRequest();

        self::assertSame([], self::names($this->fresh($user)->getPolicies()));
    }

    /**
     * Moving a role under a parent that holds a policy, or out from under it,
     * reaches the role's holders on the next request.
     *
     * @return void
     */
    public function testAReparentedRolesPoliciesTakeEffectOnTheNextRequest(): void
    {
        $publisher = Role::create(['name' => 'publisher']);
        $editor    = Role::create(['name' => 'editor']);
        $user      = StubIdentity::create(['id' => 'user-1']);

        $publisher->attachPolicy(Policy::create(['name' => 'publishers', 'document' => ['version' => 1, 'statements' => []]]));
        $user->assignRole($editor);

        self::assertSame([], self::names($user->getPolicies()));

        $this->nextRequest();
        $this->app?->make(RoleService::class)->setParent($editor, $publisher);
        $this->nextRequest();

        self::assertSame(['publishers'], self::names($this->fresh($user)->getPolicies()));

        $this->nextRequest();
        $this->app?->make(RoleService::class)->setParent($editor, null);
        $this->nextRequest();

        self::assertSame([], self::names($this->fresh($user)->getPolicies()));
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
     * A policy attached to or detached from a resource bumps the version the
     * resources of its type share, for a record and for the whole type alike,
     * and nothing of another type.
     *
     * @return void
     */
    public function testResourceAttachmentsBumpTheirType(): void
    {
        $operation = Operation::begin();
        $policy    = new Reference('policy', 'policy-1');
        $keys      = Invalidation::keys($this->versions(), [
            new ResourcePolicyAttached($operation, 'posts', '7', $policy, 'sharing', GrantScope::platform()),
            new ResourcePolicyDetached($operation, 'posts', null, $policy, 'sharing', GrantScope::platform()),
            new ResourcePolicyAttached($operation, 'docs', null, $policy, 'sharing', GrantScope::platform()),
        ]);

        self::assertSame([$this->versions()->resourcePoliciesKey('posts'), $this->versions()->resourcePoliciesKey('docs')], $keys);
    }

    /**
     * Setting, replacing and removing a boundary each bump the grantee, and
     * nothing else.
     *
     * @return void
     */
    public function testBoundaryChangesBumpTheGrantee(): void
    {
        $user    = StubIdentity::create(['id' => 'user-1']);
        $role    = Role::create(['name' => 'editor']);
        $first   = Policy::create(['name' => 'first-cap', 'document' => ['version' => 1, 'statements' => []]]);
        $second  = Policy::create(['name' => 'second-cap', 'document' => ['version' => 1, 'statements' => []]]);
        $service = $this->app?->make(BoundaryService::class);
        $grantee = [$this->versions()->granteeKey($user)];

        self::assertNotNull($service);
        self::assertSame($grantee, $this->bumpedBy(static fn () => $service->set($user, $first), $user, $role, $first));
        self::assertSame($grantee, $this->bumpedBy(static fn () => $service->set($user, $second), $user, $role, $first));
        self::assertSame($grantee, $this->bumpedBy(static fn () => $service->remove($user), $user, $role, $first));
        self::assertSame([], $this->bumpedBy(static fn () => $service->remove($user), $user, $role, $first));
    }

    /**
     * A boundary set, replaced or removed, and its policy rewritten, takes
     * effect on the next request, whatever the entries were built from.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABoundaryChangeTakesEffectOnTheNextRequest(): void
    {
        $user     = StubIdentity::create(['id' => 'user-1']);
        $policy   = Policy::create(['name' => 'cap', 'document' => ['version' => 1, 'statements' => [['effect' => 'allow', 'actions' => ['posts:read']]]]]);
        $service  = $this->app?->make(BoundaryService::class);
        $policies = $this->app?->make(PolicyService::class);
        $actions  = function () use ($user): array {
            $this->nextRequest();

            return \array_map(static fn (EvaluationPolicy $boundary): array => $boundary->statements[0]->actions ?? [], BoundaryResolver::boundariesFor($this->fresh($user)));
        };

        self::assertNotNull($service);
        self::assertNotNull($policies);
        self::assertSame([], $actions());

        $service->set($user, $policy);

        self::assertSame([['posts:read']], $actions());

        $policies->rewrite($policy, ['version' => 1, 'statements' => [['effect' => 'allow', 'actions' => ['posts:edit']]]]);

        self::assertSame([['posts:edit']], $actions());

        $service->remove($user);

        self::assertSame([], $actions());
    }

    /**
     * Setting and removing a guardrail each bump the version every guardrail
     * entry shares, and nothing else; a change that changes nothing bumps
     * nothing. The guardrail allows managing guardrails, so the actor may still
     * remove it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testGuardrailChangesBumpTheGuardrails(): void
    {
        $user    = StubIdentity::create(['id' => 'user-1']);
        $role    = Role::create(['name' => 'editor']);
        $policy  = Policy::create(['name' => 'rail', 'document' => ['version' => 1, 'statements' => [['effect' => 'allow', 'actions' => ['authorization:*']]]]]);
        $service = $this->app?->make(GuardrailService::class);
        $actor   = self::guardrailManager();
        $key     = [$this->versions()->guardrailsKey()];

        // A first check pins every version it reads, so what follows is told
        // apart from a version given its first token.
        self::assertTrue(Authorization::for($actor)->can(PackagePermissions::GUARDRAILS_MANAGE));
        self::assertNotNull($service);
        self::assertSame($key, $this->bumpedBy(static fn () => $service->set($policy, null, $actor), $user, $role, $policy));
        self::assertSame([], $this->bumpedBy(static fn () => $service->set($policy, null, $actor), $user, $role, $policy));
        self::assertSame($key, $this->bumpedBy(static fn () => $service->remove($policy, null, $actor), $user, $role, $policy));
        self::assertSame([], $this->bumpedBy(static fn () => $service->remove($policy, null, $actor), $user, $role, $policy));
    }

    /**
     * A guardrail set or removed takes effect on the next request, however the
     * entries were built.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGuardrailChangeTakesEffectOnTheNextRequest(): void
    {
        $policy  = Policy::create(['name' => 'rail', 'document' => ['version' => 1, 'statements' => [['effect' => 'allow', 'actions' => ['posts:read', 'authorization:*']]]]]);
        $service = $this->app?->make(GuardrailService::class);
        $actor   = self::guardrailManager();
        $names   = function (): array {
            $this->nextRequest();

            return self::names((new GuardrailResolver)->guardrailsFor(null));
        };

        self::assertNotNull($service);
        self::assertSame([], $names());

        $service->set($policy, null, $actor);

        self::assertSame(['rail'], $names());

        $service->remove($policy, null, $actor);

        self::assertSame([], $names());
    }

    /**
     * Return an identity that holds the right to manage guardrails
     * platform-wide.
     *
     * @return \Tests\Feature\Stubs\StubIdentity
     */
    private static function guardrailManager(): StubIdentity
    {
        $actor = StubIdentity::create(['id' => 'admin-1']);

        $actor->givePermission(Permission::create(['name' => PackagePermissions::GUARDRAILS_MANAGE]));

        return $actor;
    }

    /**
     * Return the version keys among the user's, the role's and the policy's,
     * and, with the role as a grantee, the role's as a grantee and the one the
     * role policies share, whose tokens the write changed.
     *
     * @param  \Closure(): mixed  $write
     * @param  \Tests\Feature\Stubs\StubIdentity  $user
     * @param  \SineMacula\Laravel\Authorization\Models\Role  $role
     * @param  \SineMacula\Laravel\Authorization\Models\Policy|null  $policy
     * @param  bool  $asGrantee
     * @return list<string>
     */
    private function bumpedBy(\Closure $write, StubIdentity $user, Role $role, ?Policy $policy = null, bool $asGrantee = false): array
    {
        $keys = [$this->versions()->roleKey($role->id), $this->versions()->granteeKey($user)];

        if ($policy !== null) {
            $keys[] = $this->versions()->policyKey($policy->id);
            $keys[] = $this->versions()->resourcePoliciesKey();
            $keys[] = $this->versions()->boundariesKey();
            $keys[] = $this->versions()->guardrailsKey();
        }

        if ($asGrantee) {
            $keys = [...$keys, $this->versions()->granteeKey($role), $this->versions()->rolePoliciesKey()];
        }

        $before = $this->versions()->tokens($keys);

        $write();

        $after = $this->versions()->tokens($keys);

        return \array_values(\array_filter($keys, static fn (string $key): bool => ($before[$key] ?? null) !== ($after[$key] ?? null)));
    }

    /**
     * Return the names of the policies.
     *
     * @param  array<int, \SineMacula\Laravel\Authorization\Evaluation\Policy>  $policies
     * @return list<string>
     */
    private static function names(array $policies): array
    {
        return \array_values(\array_map(static fn (EvaluationPolicy $policy): string => $policy->name, $policies));
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
