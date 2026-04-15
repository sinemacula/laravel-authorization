<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Evaluation\EvaluationResult;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Events\AuthorizationFailed;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Authorization\Events\PermissionGranted;
use SineMacula\Laravel\Authorization\Events\PermissionRevoked;
use SineMacula\Laravel\Authorization\Events\PolicyAttached;
use SineMacula\Laravel\Authorization\Events\PolicyDetached;
use SineMacula\Laravel\Authorization\Events\RoleAssigned;
use SineMacula\Laravel\Authorization\Events\RoleRevoked;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Exceptions\UnknownPermissionException;
use SineMacula\Laravel\Authorization\Exceptions\UnknownRoleException;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Traits\HasPermissions;
use SineMacula\Laravel\Authorization\Traits\HasPolicies;
use SineMacula\Laravel\Authorization\Traits\HasRoles;
use Tests\Feature\Stubs\StubAuthorizable;
use Tests\TestCase;

/**
 * End-to-end feature tests exercising the authorization manager, the
 * Eloquent traits, and the RBAC / policy interplay against a live
 * SQLite schema.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthorizationManager::class)]
#[CoversClass(HasRoles::class)]
#[CoversClass(HasPermissions::class)]
#[CoversClass(HasPolicies::class)]
final class AuthorizationManagerTest extends TestCase
{
    /**
     * Anonymous resolver yields implicit deny on can() and throws from authorize().
     *
     * @return void
     */
    public function testAnonymousPrincipalIsImplicitlyDenied(): void
    {
        self::assertFalse(Authorization::can('posts:create'));

        $this->expectException(AuthorizationException::class);
        Authorization::authorize('posts:create');
    }

    /**
     * RBAC allow via direct permission.
     *
     * @return void
     */
    public function testDirectPermissionGrantsAllow(): void
    {
        Permission::create(['id' => '01J0000000000000000000POS1', 'name' => 'posts:create', 'guard_name' => 'web']);

        $user = StubAuthorizable::create(['id' => '01J0000000000000000000USR1']);
        $user->givePermission('posts:create');

        $result = Authorization::for($user)->evaluate('posts:create');
        self::assertTrue($result->allowed);
        self::assertSame(EvaluationResult::REASON_RBAC_ALLOW, $result->reason);
    }

    /**
     * RBAC allow via role inheritance.
     *
     * @return void
     */
    public function testRoleInheritedPermissionGrantsAllow(): void
    {
        $role       = Role::create(['id' => '01J0000000000000000000ROL1', 'name' => 'editor', 'guard_name' => 'web']);
        $permission = Permission::create(['id' => '01J0000000000000000000POS2', 'name' => 'posts:update', 'guard_name' => 'web']);
        $role->permissions()->attach($permission->getKey());

        $user = StubAuthorizable::create(['id' => '01J0000000000000000000USR2']);
        $user->assignRole('editor');

        self::assertTrue($user->hasPermission('posts:update'));
        self::assertTrue(Authorization::for($user)->can('posts:update'));
    }

    /**
     * Explicit policy deny overrides RBAC allow.
     *
     * @return void
     */
    public function testExplicitDenyOverridesRoleAllow(): void
    {
        $role       = Role::create(['id' => '01J0000000000000000000ROL2', 'name' => 'admin', 'guard_name' => 'web']);
        $permission = Permission::create(['id' => '01J0000000000000000000POS3', 'name' => 'posts:delete', 'guard_name' => 'web']);
        $role->permissions()->attach($permission->getKey());

        $policy = Policy::create([
            'id'       => '01J0000000000000000000POL1',
            'name'     => 'deny-posts-delete',
            'document' => [
                'name'       => 'deny-posts-delete',
                'statements' => [['effect' => 'deny', 'actions' => ['posts:delete']]],
            ],
        ]);

        $user = StubAuthorizable::create(['id' => '01J0000000000000000000USR3']);
        $user->assignRole('admin');
        $user->attachPolicy($policy);

        $result = Authorization::for($user)->evaluate('posts:delete');
        self::assertFalse($result->allowed);
        self::assertSame(EvaluationResult::REASON_EXPLICIT_DENY, $result->reason);
    }

    /**
     * Removing the deny statement flips the decision back to allow.
     *
     * @return void
     */
    public function testRemovingDenyFlipsDecision(): void
    {
        $role       = Role::create(['id' => '01J0000000000000000000ROL3', 'name' => 'admin', 'guard_name' => 'web']);
        $permission = Permission::create(['id' => '01J0000000000000000000POS4', 'name' => 'posts:delete', 'guard_name' => 'web']);
        $role->permissions()->attach($permission->getKey());

        $policy = Policy::create([
            'id'       => '01J0000000000000000000POL2',
            'name'     => 'deny-posts-delete',
            'document' => [
                'name'       => 'deny-posts-delete',
                'statements' => [['effect' => 'deny', 'actions' => ['posts:delete']]],
            ],
        ]);

        $user = StubAuthorizable::create(['id' => '01J0000000000000000000USR4']);
        $user->assignRole('admin');
        $user->attachPolicy($policy);

        self::assertFalse(Authorization::for($user)->can('posts:delete'));

        $user->detachPolicy($policy);

        self::assertTrue(Authorization::for($user)->can('posts:delete'));
    }

    /**
     * Role assignment is idempotent and events fire.
     *
     * @return void
     */
    public function testRoleAssignmentIsIdempotentAndEmitsEvents(): void
    {
        Event::fake();

        Role::create(['id' => '01J0000000000000000000ROL4', 'name' => 'writer', 'guard_name' => 'web']);
        $user = StubAuthorizable::create(['id' => '01J0000000000000000000USR5']);

        $user->assignRole('writer');
        $user->assignRole('writer');

        self::assertCount(1, $user->roles()->get());
        Event::assertDispatched(RoleAssigned::class);

        $user->revokeRole('writer');
        self::assertCount(0, $user->fresh()?->roles()->get() ?? []);
        Event::assertDispatched(RoleRevoked::class);
    }

    /**
     * Unknown role raises typed exception.
     *
     * @return void
     */
    public function testUnknownRoleThrowsTyped(): void
    {
        $this->expectException(UnknownRoleException::class);

        StubAuthorizable::create(['id' => '01J0000000000000000000USR6'])->assignRole('nope');
    }

    /**
     * Unknown permission raises typed exception.
     *
     * @return void
     */
    public function testUnknownPermissionThrowsTyped(): void
    {
        $this->expectException(UnknownPermissionException::class);

        StubAuthorizable::create(['id' => '01J0000000000000000000USR7'])->givePermission('nope');
    }

    /**
     * Sync replaces the role set and triggers a round-trip through the DB.
     *
     * @return void
     */
    public function testSyncRolesReplacesSet(): void
    {
        Role::create(['id' => '01J0000000000000000000ROL5', 'name' => 'a', 'guard_name' => 'web']);
        Role::create(['id' => '01J0000000000000000000ROL6', 'name' => 'b', 'guard_name' => 'web']);
        Role::create(['id' => '01J0000000000000000000ROL7', 'name' => 'c', 'guard_name' => 'web']);

        $user = StubAuthorizable::create(['id' => '01J0000000000000000000USR8']);
        $user->syncRoles(['a', 'b']);
        self::assertSame(['a', 'b'], self::sortedValues($user->fresh()?->getRoles() ?? []));

        $user->syncRoles(['c']);
        self::assertSame(['c'], $user->fresh()?->getRoles());
    }

    /**
     * Policy attach/detach emits events.
     *
     * @return void
     */
    public function testPolicyEventsFire(): void
    {
        Event::fake();

        $policy = Policy::create([
            'id'       => '01J0000000000000000000POL3',
            'name'     => 'event-policy',
            'document' => ['statements' => [['effect' => 'allow', 'actions' => ['x']]]],
        ]);

        $user = StubAuthorizable::create(['id' => '01J0000000000000000000USR9']);
        $user->attachPolicy($policy);
        $user->detachPolicy($policy);

        Event::assertDispatched(PolicyAttached::class);
        Event::assertDispatched(PolicyDetached::class);
    }

    /**
     * Permission events fire.
     *
     * @return void
     */
    public function testPermissionEventsFire(): void
    {
        Event::fake();

        Permission::create(['id' => '01J0000000000000000000POS5', 'name' => 'ev:do', 'guard_name' => 'web']);
        $user = StubAuthorizable::create(['id' => '01J00000000000000000USR10']);

        $user->givePermission('ev:do');
        $user->revokePermission('ev:do');

        Event::assertDispatched(PermissionGranted::class);
        Event::assertDispatched(PermissionRevoked::class);
    }

    /**
     * Gate parity — Gate::allows and Authorization::can return identical verdicts.
     *
     * @return void
     */
    public function testGateParity(): void
    {
        /** @var \Illuminate\Contracts\Config\Repository $config */
        $config = $this->app->make('config');
        $config->set('authorization.permission_enums', [\Tests\Feature\Stubs\PermissionEnum::class]);

        (new \SineMacula\Laravel\Authorization\AuthorizationServiceProvider($this->app))->boot();

        Permission::create(['id' => '01J00000000000000000POS11', 'name' => 'posts:create', 'guard_name' => 'web']);

        $user = StubAuthorizable::create(['id' => '01J00000000000000000USR11']);
        $user->givePermission('posts:create');

        self::assertTrue(Authorization::for($user)->can('posts:create'));
        self::assertTrue(\Illuminate\Support\Facades\Gate::forUser($user)->allows('posts:create'));
    }

    /**
     * authorize() fires AuthorizationFailed and DecisionEvaluated before throwing.
     *
     * @return void
     */
    public function testAuthorizationFailedEventFires(): void
    {
        Event::fake();

        try {
            Authorization::authorize('nope');
        } catch (AuthorizationException) {
            // Expected.
        }

        Event::assertDispatched(DecisionEvaluated::class);
        Event::assertDispatched(AuthorizationFailed::class);
    }

    /**
     * withPolicies scope overrides principal-attached policies.
     *
     * @return void
     */
    public function testWithPoliciesOverridesPrincipalPolicies(): void
    {
        $user = StubAuthorizable::create(['id' => '01J00000000000000000USR12']);

        $override = EvaluationPolicy::fromArray([
            'name'       => 'ad-hoc',
            'statements' => [['effect' => 'allow', 'actions' => ['ad:hoc']]],
        ]);

        $result = Authorization::for($user)->withPolicies([$override])->evaluate('ad:hoc');

        self::assertTrue($result->allowed);
        self::assertSame(EvaluationResult::REASON_EXPLICIT_ALLOW, $result->reason);
    }

    /**
     * Spatie aliases mirror the canonical trait methods.
     *
     * @return void
     */
    public function testSpatieAliasesMirrorCanonical(): void
    {
        Permission::create(['id' => '01J00000000000000000POS12', 'name' => 'spatie:do', 'guard_name' => 'web']);
        Role::create(['id' => '01J0000000000000000000ROL8', 'name' => 'spatie-role', 'guard_name' => 'web']);

        $user = StubAuthorizable::create(['id' => '01J00000000000000000USR13']);

        // Aliases mirror canonical helpers.
        $user->givePermissionTo('spatie:do');
        $user->assignRole('spatie-role');

        self::assertTrue($user->hasPermissionTo('spatie:do'));
        self::assertSame(['spatie:do'], $user->getPermissionNames());
        self::assertSame(['spatie-role'], $user->getRoleNames());

        $user->revokePermissionTo('spatie:do');
        $user->removeRole('spatie-role');

        self::assertFalse($user->hasPermission('spatie:do'));
        self::assertSame([], $user->getRoles());
    }

    /**
     * Sort an array of strings.
     *
     * @param  array<int, string>  $values
     * @return array<int, string>
     */
    private static function sortedValues(array $values): array
    {
        \sort($values);

        return \array_values($values);
    }
}
