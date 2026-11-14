<?php

declare(strict_types = 1);

namespace Tests\Feature\Resolvers;

use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Repository;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Cache\Resolution;
use SineMacula\Laravel\Authorization\Cache\ResolutionPins;
use SineMacula\Laravel\Authorization\Cache\VersionedStore;
use SineMacula\Laravel\Authorization\Evaluation\InvalidPolicyDocumentException;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Evaluation\Statement;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Resolvers\GrantResolver;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use Tests\Concerns\ActivatesBreakGlass;
use Tests\Feature\Stubs\RecordingLogger;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for resolving what an identity's grants come to, the versions
 * each resolution pins, and the expiry it reports.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GrantResolver::class)]
final class GrantResolverTest extends TestCase
{
    use ActivatesBreakGlass;

    /**
     * Start the clock.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow('2026-07-01 12:00:00');
    }

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
     * Roles resolve to their names in the order they were granted, pinning each
     * role, and expire with the nearest grant.
     *
     * @return void
     */
    public function testRolesResolveInGrantOrderAndPinEachRole(): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $zeta   = Role::create(['name' => 'zeta']);
        $alpha  = Role::create(['name' => 'alpha']);
        $expiry = Carbon::parse('2026-07-01 12:10:00');

        $user->assignRole($zeta);
        $user->assignRole($alpha, $expiry);

        [$pins, $store] = self::pins();

        $resolution = GrantResolver::roles($user->roles(), $pins);

        self::assertSame(['zeta', 'alpha'], $resolution->value);
        self::assertSame(600, $resolution->expiresIn);
        self::assertTrue($resolution->stable);
        self::assertSame([$store->roleKey($zeta->id), $store->roleKey($alpha->id)], \array_keys($pins->tokens()));
    }

    /**
     * Without grants nothing resolves, and nothing expires.
     *
     * @return void
     */
    public function testNoGrantsResolveToNothing(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);

        self::assertSame([], GrantResolver::roles($user->roles(), new ResolutionPins)->value);
        self::assertNull(GrantResolver::roles($user->roles(), new ResolutionPins)->expiresIn);
        self::assertSame([], GrantResolver::permissions($user->permissions(), $user->roles(), new ResolutionPins)->value);
        self::assertSame([], GrantResolver::policies($user->policies(), new ResolutionPins)->value);

        self::assertSame(1, self::queriesFor(static fn () => GrantResolver::roles($user->roles(), new ResolutionPins)));
        self::assertSame(2, self::queriesFor(static fn () => GrantResolver::permissions($user->permissions(), $user->roles(), new ResolutionPins)));
        self::assertSame(1, self::queriesFor(static fn () => GrantResolver::policies($user->policies(), new ResolutionPins)));
        self::assertSame(1, self::queriesFor(static fn () => GrantResolver::policies($user->policies(), new ResolutionPins, $user->roles())));
    }

    /**
     * A permission granted directly and through a role is listed once, and the
     * names stay a list.
     *
     * @return void
     */
    public function testAPermissionHeldTwiceIsListedOnce(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);
        $role = Role::create(['name' => 'writer']);

        $role->givePermission(Permission::create(['name' => 'posts:read']));
        $role->givePermission(Permission::create(['name' => 'posts:write']));
        $user->givePermission('posts:read');
        $user->assignRole($role);

        $names = GrantResolver::permissions($user->permissions(), $user->roles(), new ResolutionPins)->value;

        self::assertSame([0, 1], \array_keys($names));
        self::assertEqualsCanonicalizing(['posts:read', 'posts:write'], $names);
    }

    /**
     * A role deleted while the resolution runs, after the grants were read, is
     * left out, and the roles after it are still listed.
     *
     * @return void
     */
    public function testARoleDeletedWhileResolvingIsLeftOut(): void
    {
        $user  = StubIdentity::create(['id' => 'user-1']);
        $first = Role::create(['name' => 'first']);

        $user->assignRole($first);
        $user->assignRole(Role::create(['name' => 'second']));

        $store = new VersionedStore(new Repository(self::onFirstPin(static fn () => DB::table('roles')->where('id', $first->id)->delete())), 'authz');

        self::assertSame(['second'], GrantResolver::roles($user->roles(), new ResolutionPins($store))->value);
    }

    /**
     * Permissions resolve to the direct grants and those held through the roles
     * and their ancestors, each once, pinning every role read, and expire with
     * the nearest grant of either kind.
     *
     * @return void
     */
    public function testPermissionsComeDirectlyAndThroughTheHierarchy(): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $parent = Role::create(['name' => 'reader']);
        $role   = Role::create(['name' => 'writer', 'parent_id' => $parent->id]);

        $parent->givePermission(Permission::create(['name' => 'posts:read']));
        $role->givePermission(Permission::create(['name' => 'posts:write']));

        $user->givePermission('posts:read', Carbon::parse('2026-07-01 12:05:00'));
        $user->assignRole($role, Carbon::parse('2026-07-01 12:10:00'));

        [$pins, $store] = self::pins();

        $resolution = GrantResolver::permissions($user->permissions(), $user->roles(), $pins);

        self::assertEqualsCanonicalizing(['posts:read', 'posts:write'], $resolution->value);
        self::assertCount(2, $resolution->value);
        self::assertSame(300, $resolution->expiresIn);
        self::assertTrue($resolution->stable);
        self::assertEqualsCanonicalizing([$store->roleKey($role->id), $store->roleKey($parent->id)], \array_keys($pins->tokens()));
    }

    /**
     * A role moved under a parent the resolution had not read, between reading
     * the hierarchy and its permissions, still resolves to the moved role's
     * permissions afresh, expiring with them, but is marked unstable so it is
     * not stored.
     *
     * @return void
     */
    public function testAHierarchyThatMovesWhileResolvingIsUnstable(): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $parent = Role::create(['name' => 'publisher']);
        $role   = Role::create(['name' => 'editor']);

        $parent->givePermission(Permission::create(['name' => 'posts:publish']), Carbon::parse('2026-07-01 12:01:00'));
        $user->assignRole($role);

        $store = new VersionedStore(new Repository(self::onFirstPin(static fn () => DB::table('roles')->where('id', $role->id)->update(['parent_id' => $parent->id]))), 'authz');

        $resolution = GrantResolver::permissions($user->permissions(), $user->roles(), new ResolutionPins($store));

        self::assertSame(['posts:publish'], $resolution->value);
        self::assertSame(60, $resolution->expiresIn);
        self::assertFalse($resolution->stable);
    }

    /**
     * A role read through a break-glass activation names the activation behind
     * each permission and policy it, or a role above it, gives, a role also
     * granted included, and nothing behind a grant no activation gave; a
     * grantee holding none names nothing.
     *
     * @return void
     */
    public function testAnActivatedRoleNamesItsActivationBehindWhatItGives(): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $other  = StubIdentity::create(['id' => 'user-2']);
        $parent = Role::create(['name' => 'publisher']);
        $role   = Role::create(['name' => 'responder', 'parent_id' => $parent->id]);
        $policy = Policy::create(['name' => 'publishers', 'document' => ['version' => 1, 'statements' => []]]);
        $own    = Policy::create(['name' => 'own', 'document' => ['version' => 1, 'statements' => []]]);

        $parent->givePermission(Permission::create(['name' => 'posts:publish']));
        $parent->attachPolicy($policy);
        $role->givePermission(Permission::create(['name' => 'posts:create']));
        $user->givePermission(Permission::create(['name' => 'posts:read']));
        $user->attachPolicy($own);
        $other->assignRole($role);

        $activation = self::activate($user, $role);
        $expected   = ['posts:create' => [$activation->id], 'posts:publish' => [$activation->id]];

        $resolved = GrantResolver::permissions($user->permissions(), $user->roles(), self::pins()[0]);

        self::assertEquals($expected, $resolved->activations);
        self::assertNull($resolved->routes);
        self::assertTrue($resolved->stable);
        self::assertSame([$policy->id => [$activation->id]], GrantResolver::policies($user->policies(), self::pins()[0], $user->roles())->activations);
        self::assertSame([], GrantResolver::permissions($other->permissions(), $other->roles(), self::pins()[0])->activations);
        self::assertSame([], GrantResolver::policies($other->policies(), self::pins()[0], $other->roles())->activations);

        $user->assignRole($role);

        self::assertEquals($expected, GrantResolver::permissions($user->permissions(), $user->roles(), self::pins()[0])->activations);
    }

    /**
     * A resolution holding an activated role whose hierarchy moves while it
     * runs reads the roles afresh by role, still naming the activation behind
     * what the role now gives, and says no routes.
     *
     * @return void
     */
    public function testAMovedHierarchyStillNamesTheActivation(): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $parent = Role::create(['name' => 'publisher']);
        $role   = Role::create(['name' => 'responder']);

        $parent->givePermission(Permission::create(['name' => 'posts:publish']), Carbon::parse('2026-07-01 12:01:00'));

        $activation = self::activate($user, $role);
        $move       = static fn () => DB::table('roles')->where('id', $role->id)->update(['parent_id' => $parent->id]);
        $store      = new VersionedStore(new Repository(self::onFirstPin($move)), 'authz');
        $resolution = GrantResolver::permissions($user->permissions(), $user->roles(), new ResolutionPins($store, true));

        self::assertSame(['posts:publish'], $resolution->value);
        self::assertSame(60, $resolution->expiresIn);
        self::assertFalse($resolution->stable);
        self::assertNull($resolution->routes);
        self::assertSame(['posts:publish' => [$activation->id]], $resolution->activations);
    }

    /**
     * A role's grant of a permission that expires sooner than any grant of the
     * identity's bounds the resolution, and one that has expired is left out.
     *
     * @return void
     */
    public function testARolesPermissionThatExpiresSoonerBoundsTheResolution(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);
        $role = Role::create(['name' => 'writer']);

        $role->givePermission(Permission::create(['name' => 'posts:write']), Carbon::parse('2026-07-01 12:02:00'));
        $role->givePermission(Permission::create(['name' => 'posts:lapsed']), Carbon::parse('2026-07-01 11:00:00'));
        $user->givePermission(Permission::create(['name' => 'posts:read']), Carbon::parse('2026-07-01 12:05:00'));
        $user->assignRole($role);

        $resolution = GrantResolver::permissions($user->permissions(), $user->roles(), new ResolutionPins);

        self::assertEqualsCanonicalizing(['posts:read', 'posts:write'], $resolution->value);
        self::assertSame(120, $resolution->expiresIn);
    }

    /**
     * The keys of the roles reached resolve to the roles held and, with the
     * hierarchy enabled, those above them, each once, pinning every role
     * reached, expiring with the nearest grant, in three queries.
     *
     * @return void
     */
    public function testRoleKeysComeThroughTheHierarchyAndPinEachRole(): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $parent = Role::create(['name' => 'reader']);
        $role   = Role::create(['name' => 'writer', 'parent_id' => $parent->id]);

        $user->assignRole($role, Carbon::parse('2026-07-01 12:10:00'));
        $user->assignRole($parent);

        [$pins, $store] = self::pins();

        $resolution = null;
        $queries    = self::queriesFor(static function () use ($user, $pins, &$resolution): void {
            $resolution = GrantResolver::roleKeys($user->roles(), $pins);
        });

        self::assertInstanceOf(Resolution::class, $resolution);
        self::assertEqualsCanonicalizing([$role->id, $parent->id], $resolution->value);
        self::assertCount(2, $resolution->value);
        self::assertSame(600, $resolution->expiresIn);
        self::assertTrue($resolution->stable);
        self::assertSame(3, $queries);
        self::assertEqualsCanonicalizing([$store->roleKey($role->id), $store->roleKey($parent->id)], \array_keys($pins->tokens()));

        config()->set('authorization.hierarchy.enabled', false);

        self::assertEqualsCanonicalizing([$role->id, $parent->id], GrantResolver::roleKeys($user->roles(), new ResolutionPins)->value);

        $user->revokeRole($parent);

        self::assertSame([$role->id], GrantResolver::roleKeys($user->roles(), new ResolutionPins)->value);
    }

    /**
     * A role moved under a parent the resolution had not read still resolves to
     * the parent's key, read afresh, but is marked unstable so it is not
     * stored.
     *
     * @return void
     */
    public function testRoleKeysWhoseHierarchyMovesWhileResolvingAreUnstable(): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $parent = Role::create(['name' => 'publisher']);
        $role   = Role::create(['name' => 'editor']);

        $user->assignRole($role);

        $store = new VersionedStore(new Repository(self::onFirstPin(static fn () => DB::table('roles')->where('id', $role->id)->update(['parent_id' => $parent->id]))), 'authz');

        $resolution = GrantResolver::roleKeys($user->roles(), new ResolutionPins($store));

        self::assertFalse($resolution->stable);
        self::assertEqualsCanonicalizing([$role->id, $parent->id], $resolution->value);
    }

    /**
     * A role read through a break-glass activation names the activation behind
     * its key and each key above it, also when the hierarchy moves meanwhile; a
     * role granted alone, and a grantee holding no activated role, name none.
     *
     * @return void
     */
    public function testAnActivatedRoleNamesItsActivationBehindItsKeys(): void
    {
        $user    = StubIdentity::create(['id' => 'user-1']);
        $parent  = Role::create(['name' => 'publisher']);
        $role    = Role::create(['name' => 'responder', 'parent_id' => $parent->id]);
        $granted = Role::create(['name' => 'editor']);
        $moved   = Role::create(['name' => 'auditor']);
        $above   = Role::create(['name' => 'lead']);

        $user->assignRole($granted);

        self::assertSame([], GrantResolver::roleKeys($user->roles(), new ResolutionPins)->activations);

        $activation = self::activate($user, $role);
        $resolution = GrantResolver::roleKeys($user->roles(), new ResolutionPins);

        self::assertEqualsCanonicalizing([$granted->id, $role->id, $parent->id], $resolution->value);
        self::assertSame([$role->id => [$activation->id], $parent->id => [$activation->id]], $resolution->activations);

        $other = self::activate($user, $moved);
        $store = new VersionedStore(new Repository(self::onFirstPin(static fn () => DB::table('roles')->where('id', $moved->id)->update(['parent_id' => $above->id]))), 'authz');
        $fresh = GrantResolver::roleKeys($user->roles(), new ResolutionPins($store));

        self::assertFalse($fresh->stable);
        self::assertSame([$other->id], $fresh->activations[$above->id] ?? null);
        self::assertSame([$other->id], $fresh->activations[$moved->id] ?? null);
    }

    /**
     * A resolution tracking grant usage says the routes behind each permission
     * it finds.
     *
     * @return void
     */
    public function testARoutedResolutionSaysTheRoutesBehindEachPermission(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);
        $role = Role::create(['name' => 'editor']);

        $role->givePermission(Permission::create(['name' => 'posts:edit']));
        $user->assignRole($role);

        $routes = GrantResolver::permissions($user->permissions(), $user->roles(), new ResolutionPins(null, true))->routes;

        self::assertNotNull($routes);
        self::assertSame(['posts:edit'], $routes->names());
    }

    /**
     * Policies resolve in the order they were attached, pinning each, and
     * expire with the nearest attachment.
     *
     * @return void
     */
    public function testPoliciesResolveInAttachmentOrderAndPinEachPolicy(): void
    {
        $user    = StubIdentity::create(['id' => 'user-1']);
        $writers = Policy::create(['name' => 'writers', 'document' => ['version' => 1, 'statements' => []]]);
        $readers = Policy::create(['name' => 'readers', 'document' => ['version' => 1, 'statements' => []]]);

        $user->attachPolicy($writers, Carbon::parse('2026-07-01 12:01:00'));
        $user->attachPolicy($readers);

        [$pins, $store] = self::pins();

        $resolution = GrantResolver::policies($user->policies(), $pins);

        self::assertSame(['writers', 'readers'], \array_map(static fn (EvaluationPolicy $policy): string => $policy->name, $resolution->value));
        self::assertSame(60, $resolution->expiresIn);
        self::assertSame([$store->policyKey($writers->id), $store->policyKey($readers->id)], \array_keys($pins->tokens()));
    }

    /**
     * Given the roles, policies come directly and through the roles, each once,
     * pinning the version every role's attachments share first, and expire with
     * the nearest of the attachments and the grant of the role.
     *
     * @return void
     */
    public function testPoliciesComeDirectlyAndThroughTheRoles(): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $role   = Role::create(['name' => 'editor']);
        $own    = Policy::create(['name' => 'own', 'document' => ['version' => 1, 'statements' => []]]);
        $shared = Policy::create(['name' => 'shared', 'document' => ['version' => 1, 'statements' => []]]);
        $roles  = Policy::create(['name' => 'editors', 'document' => ['version' => 1, 'statements' => []]]);

        $user->attachPolicy($own, Carbon::parse('2026-07-01 12:10:00'));
        $user->attachPolicy($shared);
        $role->attachPolicy($shared);
        $role->attachPolicy($roles);
        $user->assignRole($role, Carbon::parse('2026-07-01 12:04:00'));

        [$pins, $store] = self::pins();

        $resolution = GrantResolver::policies($user->policies(), $pins, $user->roles());
        $keys       = \array_keys($pins->tokens());

        self::assertSame(['own', 'shared', 'editors'], \array_map(static fn (EvaluationPolicy $policy): string => $policy->name, $resolution->value));
        self::assertSame(240, $resolution->expiresIn);
        self::assertTrue($resolution->stable);
        self::assertSame($store->rolePoliciesKey(), $keys[0]);
        self::assertEqualsCanonicalizing(
            [$store->rolePoliciesKey(), $store->roleKey($role->id), $store->policyKey($own->id), $store->policyKey($shared->id), $store->policyKey($roles->id)],
            $keys,
        );
    }

    /**
     * An attachment naming half a tenant, a key without a type or a type
     * without a key, and any attachment of a policy naming half a tenant, is
     * read in every scope for its denies alone, the grantee's own and a role's
     * alike: such a policy resolves with its deny statements alone, unless an
     * attachment that holds, of a policy that names no half tenant, reaches it
     * too; and such an attachment is never a route.
     *
     * @return void
     */
    public function testAnAttachmentNamingHalfATenantResolvesToItsDeniesAlone(): void
    {
        $user  = StubIdentity::create(['id' => 'user-1']);
        $role  = Role::create(['name' => 'editor']);
        $names = ['whole', 'keyless', 'mixed', 'owned', 'role half', 'role owned'];
        $made  = [];

        $statements = [['effect' => 'allow', 'actions' => ['posts:read']], ['effect' => 'deny', 'actions' => ['posts:write']]];

        foreach ($names as $name) {
            $made[$name] = Policy::create(['name' => $name, 'document' => ['statements' => $statements]]);
        }

        $user->assignRole($role);
        $user->attachPolicy($made['whole']);
        $user->attachPolicy($made['mixed']);
        $role->attachPolicy($made['role owned']);

        $own  = ['authorizable_type' => $user->getMorphClass(), 'authorizable_id' => 'user-1', 'include_subtree' => true];
        $held = ['authorizable_type' => $role->getMorphClass(), 'authorizable_id' => $role->id, 'include_subtree' => true];

        DB::table('authorizable_policies')->insert([
            ['policy_id' => $made['keyless']->id, ...$own, 'tenant_type' => 'tenant', 'tenant_id' => null],
            ['policy_id' => $made['mixed']->id, ...$own, 'tenant_type' => null, 'tenant_id' => 't-1'],
            ['policy_id' => $made['owned']->id, ...$own, 'tenant_type' => 'tenant', 'tenant_id' => 't-2'],
            ['policy_id' => $made['role half']->id, ...$held, 'tenant_type' => null, 'tenant_id' => 't-1'],
        ]);
        DB::table('policies')->whereIn('id', [$made['owned']->id, $made['role owned']->id])->update(['tenant_type' => 'tenant', 'tenant_id' => null]);

        $resolution = GrantResolver::policies($user->policies(), new ResolutionPins(null, true), $user->roles());
        $effects    = [];

        // A deny keeps the position it holds in its document.
        foreach ($resolution->value as $policy) {
            $effects[$policy->name] = \array_map(static fn (Statement $statement): string => $statement->effect->value, $policy->statements);
        }

        \ksort($effects);

        $denies = [1 => 'deny'];

        $both = ['allow', 'deny'];

        self::assertSame(['keyless' => $denies, 'mixed' => $both, 'owned' => $denies, 'role half' => $denies, 'role owned' => $denies, 'whole' => $both], $effects);

        $routed = $resolution->routes?->names() ?? [];

        self::assertContains($made['whole']->id, $routed);
        self::assertNotContains($made['keyless']->id, $routed);
        self::assertNotContains($made['role half']->id, $routed);
        self::assertEqualsCanonicalizing(
            [$made['keyless']->id, $made['mixed']->id, $made['owned']->id],
            GrantResolver::deniedEverywhere($user->policies(), ['policy_id'])->pluck('policy_id')->all(),
        );
    }

    /**
     * An attachment naming half a tenant counts for its denies alone in its own
     * application only: one made for an application is read neither with no
     * application nor in another, and is read, its denies alone, in its own.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAttachmentNamingHalfATenantCountsInItsApplicationAlone(): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $policy = Policy::create(['name' => 'mobile only', 'document' => ['statements' => [['effect' => 'deny', 'actions' => ['posts:write']]]]]);

        DB::table('authorizable_policies')->insert([
            'policy_id'         => $policy->id,
            'authorizable_type' => $user->getMorphClass(),
            'authorizable_id'   => 'user-1',
            'include_subtree'   => true,
            'tenant_type'       => null,
            'tenant_id'         => 't-1',
            'application'       => 'mobile',
        ]);

        $denied   = static fn (): array => GrantResolver::deniedEverywhere($user->policies(), ['policy_id'])->pluck('policy_id')->all();
        $named    = static fn (EvaluationPolicy $read): string => $read->name;
        $resolved = static fn (): array => \array_map($named, GrantResolver::policies($user->policies(), new ResolutionPins)->value);

        self::assertSame([], $denied());
        self::assertSame([], $resolved());
        self::assertSame([], TenantScope::within(null, 'web', $denied));
        self::assertSame([], TenantScope::within(null, 'web', $resolved));
        self::assertSame([$policy->id], TenantScope::within(null, 'mobile', $denied));
        self::assertSame(['mobile only'], TenantScope::within(null, 'mobile', $resolved));
    }

    /**
     * Without the roles, only the grantee's own policies resolve: nothing of
     * the roles is read or pinned, and its own attachments bound the expiry.
     *
     * @return void
     */
    public function testWithoutTheRolesOnlyTheGranteesOwnPoliciesResolve(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);
        $role = Role::create(['name' => 'editor']);
        $own  = Policy::create(['name' => 'own', 'document' => ['version' => 1, 'statements' => []]]);

        $role->attachPolicy(Policy::create(['name' => 'editors', 'document' => ['version' => 1, 'statements' => []]]), Carbon::parse('2026-07-01 12:01:00'));
        $user->attachPolicy($own, Carbon::parse('2026-07-01 12:10:00'));
        $user->assignRole($role);

        [$pins, $store] = self::pins();

        $resolution = GrantResolver::policies($user->policies(), $pins);

        self::assertSame(['own'], \array_map(static fn (EvaluationPolicy $policy): string => $policy->name, $resolution->value));
        self::assertSame(600, $resolution->expiresIn);
        self::assertSame([$store->policyKey($own->id)], \array_keys($pins->tokens()));
    }

    /**
     * Resolving leaves the grantee's relation as it was, so it reads the
     * policies afterwards as before.
     *
     * @return void
     */
    public function testResolvingLeavesTheRelationAsItWas(): void
    {
        $user     = StubIdentity::create(['id' => 'user-1']);
        $relation = $user->policies();

        $user->attachPolicy(Policy::create(['name' => 'writers', 'document' => ['version' => 1, 'statements' => []]]));
        Role::create(['name' => 'editor'])->attachPolicy(Policy::create(['name' => 'editors', 'document' => ['version' => 1, 'statements' => []]]));

        GrantResolver::policies($relation, new ResolutionPins, $user->roles());

        self::assertSame(['writers'], $relation->pluck('name')->all());
    }

    /**
     * An attachment of another grantee's inline policy, written past the write
     * paths, never resolves; the grantee's own inline policy does.
     *
     * @return void
     */
    public function testAnotherGranteesInlinePolicyNeverResolves(): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $other  = StubIdentity::create(['id' => 'user-2']);
        $theirs = $other->createInlinePolicy('theirs', ['version' => 1, 'statements' => []]);

        $user->attachPolicy($user->createInlinePolicy('mine', ['version' => 1, 'statements' => []]));
        DB::table('authorizable_policies')->insert(['policy_id' => $theirs->id, 'authorizable_type' => $user->getMorphClass(), 'authorizable_id' => 'user-1']);

        $resolution = GrantResolver::policies($user->policies(), new ResolutionPins, $user->roles());

        self::assertSame(['mine'], \array_map(static fn (EvaluationPolicy $policy): string => $policy->name, $resolution->value));
    }

    /**
     * A policy whose document cannot be read is written to the log channel and
     * its exception thrown, so it denies rather than being skipped.
     *
     * @return void
     */
    public function testAnUnreadablePolicyIsLoggedAndThrown(): void
    {
        $logger = new RecordingLogger;
        $this->app?->instance('log', $logger);

        $user   = StubIdentity::create(['id' => 'user-1']);
        $policy = Policy::create(['name' => 'broken', 'document' => ['version' => 1, 'statements' => []]]);

        $user->attachPolicy($policy);

        $unreadable = ['statements' => [['effect' => 'allow', 'actions' => ['posts:read'], 'resources' => []]]];

        DB::table('policies')->where('id', $policy->id)->update(['document' => \json_encode($unreadable)]);

        $reason = 'Invalid policy document \'broken\': Policy statement resources must be a non-empty list of non-empty strings.';

        try {
            GrantResolver::policies($user->policies(), new ResolutionPins);
            self::fail('An unreadable policy was not thrown.');
        } catch (InvalidPolicyDocumentException $exception) {
            self::assertSame($reason, $exception->getMessage());
        }

        self::assertSame([[
            'level'   => 'warning',
            'message' => "Authorization: malformed policy '{$policy->id}' denies every check for its holder: {$reason}",
            'context' => ['policy_id' => $policy->id, 'policy_name' => 'broken', 'reason' => $reason],
        ]], $logger->records);
    }

    /**
     * One policy is hydrated for evaluation under its stored name and key, as
     * the resource policy resolver hydrates each it reads.
     *
     * @return void
     */
    public function testHydratesOnePolicy(): void
    {
        $policy = Policy::create(['name' => 'readers', 'document' => ['version' => 1, 'name' => 'other', 'statements' => [['effect' => 'allow', 'actions' => ['posts:read']]]]]);

        $hydrated = GrantResolver::hydrate($policy);

        self::assertSame(['readers', $policy->id, null], [$hydrated->name, $hydrated->id, $hydrated->resource]);
        self::assertSame(['posts:read'], $hydrated->statements[0]->actions);
    }

    /**
     * Return an array store that runs the write the first time versions are
     * read, as a write committing while a resolution runs would.
     *
     * @param  \Closure(): mixed  $write
     * @return \Illuminate\Cache\ArrayStore
     */
    private static function onFirstPin(\Closure $write): ArrayStore
    {
        return new class ($write) extends ArrayStore {
            /**
             * @param  \Closure(): mixed|null  $onPin
             */
            public function __construct(

                /** The write to run; run once, then cleared. */
                private ?\Closure $onPin,
            ) {
                parent::__construct();
            }

            /**
             * Run the write the first time versions are read.
             *
             * @param  array<mixed>  $keys
             * @return array<string, mixed>
             */
            #[\Override]
            public function many(array $keys): array
            {
                if ($this->onPin !== null) {
                    ($this->onPin)();
                    $this->onPin = null;
                }

                return parent::many($keys);
            }
        };
    }

    /**
     * Count the queries the work runs.
     *
     * @param  \Closure(): mixed  $work
     * @return int
     */
    private static function queriesFor(\Closure $work): int
    {
        DB::flushQueryLog();
        DB::enableQueryLog();

        $work();

        $count = \count(DB::getQueryLog());

        DB::disableQueryLog();

        return $count;
    }

    /**
     * Return pins over a fresh store, and the store.
     *
     * @return array{0: \SineMacula\Laravel\Authorization\Cache\ResolutionPins, 1: \SineMacula\Laravel\Authorization\Cache\VersionedStore}
     */
    private static function pins(): array
    {
        $store = new VersionedStore(new Repository(new ArrayStore), 'authz');

        return [new ResolutionPins($store), $store];
    }
}
