<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Events\AuthorizationFailed;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Authorization\Events\Identity\IdentityPermissionGranted;
use SineMacula\Laravel\Authorization\Events\Identity\IdentityPermissionRevoked;
use SineMacula\Laravel\Authorization\Events\Identity\IdentityPolicyAttached;
use SineMacula\Laravel\Authorization\Events\Identity\IdentityPolicyDetached;
use SineMacula\Laravel\Authorization\Events\Identity\IdentityRoleAssigned;
use SineMacula\Laravel\Authorization\Events\Identity\IdentityRoleRevoked;
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
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * End-to-end feature tests exercising the authorization manager, the Eloquent
 * traits, and the RBAC / policy interplay against a live SQLite schema.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(AuthorizationManager::class)]
#[CoversTrait(HasRoles::class)]
#[CoversTrait(HasPermissions::class)]
#[CoversTrait(HasPolicies::class)]
final class AuthorizationManagerTest extends TestCase
{
    /**
     * Anonymous resolver yields implicit deny on can() and throws from
     * authorize().
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
        Permission::create(['id' => '7a5c8f67-eba9-492b-8a42-a49ec654b516', 'name' => 'posts:create', 'guard_name' => 'web']);

        $user = StubIdentity::create(['id' => '1705066a-b10d-4f4a-8aba-73758a3a381a']);
        $user->givePermission('posts:create');

        $decision = Authorization::for($user)->evaluate('posts:create');
        self::assertTrue($decision->allowed);
        self::assertSame(DecisionReason::RBAC_ALLOW, $decision->reason);
    }

    /**
     * RBAC allow via role inheritance.
     *
     * @return void
     */
    public function testRoleInheritedPermissionGrantsAllow(): void
    {
        $role       = Role::create(['id' => '73b70528-9653-431a-8837-48847b3ee826', 'name' => 'editor', 'guard_name' => 'web']);
        $permission = Permission::create(['id' => 'de7fb420-9d52-4329-8c2e-eb88b1cdc77c', 'name' => 'posts:update', 'guard_name' => 'web']);
        $role->permissions()->attach($permission->getKey());

        $user = StubIdentity::create(['id' => '3acbd94d-7c5c-475b-82a3-791fa9c24234']);
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
        $role       = Role::create(['id' => '5596d2e7-ed0e-4a25-8b13-556e36de93e9', 'name' => 'admin', 'guard_name' => 'web']);
        $permission = Permission::create(['id' => 'cad09583-86ca-42b3-89fc-9dde9a3020b6', 'name' => 'posts:delete', 'guard_name' => 'web']);
        $role->permissions()->attach($permission->getKey());

        $policy = Policy::create([
            'id'       => '7a5569df-ae91-42fd-8279-523c451fd857',
            'name'     => 'deny-posts-delete',
            'document' => [
                'name'       => 'deny-posts-delete',
                'statements' => [['effect' => 'deny', 'actions' => ['posts:delete']]],
            ],
        ]);

        $user = StubIdentity::create(['id' => 'd37fe6a3-e6ec-45a4-88b2-96baaf2f17c4']);
        $user->assignRole('admin');
        $user->attachPolicy($policy);

        $decision = Authorization::for($user)->evaluate('posts:delete');
        self::assertFalse($decision->allowed);
        self::assertSame(DecisionReason::EXPLICIT_DENY, $decision->reason);
    }

    /**
     * Removing the deny statement flips the decision back to allow.
     *
     * @return void
     */
    public function testRemovingDenyFlipsDecision(): void
    {
        $role       = Role::create(['id' => '892c12f1-70f5-4a5d-83c0-946bfd611a71', 'name' => 'admin', 'guard_name' => 'web']);
        $permission = Permission::create(['id' => '6d4ddc84-e926-4fa9-819b-716c3a423654', 'name' => 'posts:delete', 'guard_name' => 'web']);
        $role->permissions()->attach($permission->getKey());

        $policy = Policy::create([
            'id'       => '7692f1c6-5cb7-480c-8240-100f24f97644',
            'name'     => 'deny-posts-delete',
            'document' => [
                'name'       => 'deny-posts-delete',
                'statements' => [['effect' => 'deny', 'actions' => ['posts:delete']]],
            ],
        ]);

        $user = StubIdentity::create(['id' => '7c6fe0b1-55e4-4483-8474-9f2ade6dc73d']);
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

        Role::create(['id' => '9e294583-8b87-4fea-86ba-15de1a2f73ed', 'name' => 'writer', 'guard_name' => 'web']);
        $user = StubIdentity::create(['id' => 'd53f6d56-30fd-417c-8edc-450a2096f822']);

        $user->assignRole('writer');
        $user->assignRole('writer');

        self::assertCount(1, $user->roles()->get());
        Event::assertDispatched(IdentityRoleAssigned::class);

        $user->revokeRole('writer');
        self::assertCount(0, $user->fresh()?->roles()->get() ?? []);
        Event::assertDispatched(IdentityRoleRevoked::class);
    }

    /**
     * Unknown role raises typed exception.
     *
     * @return void
     */
    public function testUnknownRoleThrowsTyped(): void
    {
        $this->expectException(UnknownRoleException::class);

        StubIdentity::create(['id' => 'f265c4ee-d540-40df-8d50-2f4acbcd6112'])->assignRole('nope');
    }

    /**
     * Unknown permission raises typed exception.
     *
     * @return void
     */
    public function testUnknownPermissionThrowsTyped(): void
    {
        $this->expectException(UnknownPermissionException::class);

        StubIdentity::create(['id' => '4b74b79a-93c7-4b83-8e2e-fb14dc72bf8c'])->givePermission('nope');
    }

    /**
     * Sync replaces the role set and triggers a round-trip through the DB.
     *
     * @return void
     */
    public function testSyncRolesReplacesSet(): void
    {
        Role::create(['id' => '1ea0f4c9-a06c-4c53-86a7-4807d569a51c', 'name' => 'a', 'guard_name' => 'web']);
        Role::create(['id' => 'b4a0f6f6-1195-48e2-8020-eb84a104928b', 'name' => 'b', 'guard_name' => 'web']);
        Role::create(['id' => '4948f001-2d70-46c7-8b17-687e7a55479d', 'name' => 'c', 'guard_name' => 'web']);

        $user = StubIdentity::create(['id' => '1bf39684-eb97-4b99-8898-2971c1e19c35']);
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
            'id'       => 'a63d903f-96a8-4448-8a48-73767b061ece',
            'name'     => 'event-policy',
            'document' => ['statements' => [['effect' => 'allow', 'actions' => ['x']]]],
        ]);

        $user = StubIdentity::create(['id' => '0ab8aac8-e17c-4b6b-87b4-6e37afd18d0e']);
        $user->attachPolicy($policy);
        $user->detachPolicy($policy);

        Event::assertDispatched(IdentityPolicyAttached::class);
        Event::assertDispatched(IdentityPolicyDetached::class);
    }

    /**
     * Permission events fire.
     *
     * @return void
     */
    public function testPermissionEventsFire(): void
    {
        Event::fake();

        Permission::create(['id' => '7b2cc2e2-1f29-4467-8a74-844bedaac2d2', 'name' => 'ev:do', 'guard_name' => 'web']);
        $user = StubIdentity::create(['id' => '6df993ba-ca47-4224-8ecf-1742ca42e42d']);

        $user->givePermission('ev:do');
        $user->revokePermission('ev:do');

        Event::assertDispatched(IdentityPermissionGranted::class);
        Event::assertDispatched(IdentityPermissionRevoked::class);
    }

    /**
     * Gate parity — Gate::allows and Authorization::can return identical
     * verdicts.
     *
     * @return void
     */
    public function testGateParity(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make('config'); // @phpstan-ignore method.nonObject (test container is non-null)
        $config->set('authorization.permission_enums', [\Tests\Feature\Stubs\PermissionEnum::class]);

        (new \SineMacula\Laravel\Authorization\AuthorizationServiceProvider($this->app))->boot();

        Permission::create(['id' => '70be15aa-1ce5-4c1f-87a5-1c8e91a02587', 'name' => 'posts:create', 'guard_name' => 'web']);

        $user = StubIdentity::create(['id' => 'd004aa1d-ff0c-4776-8a4c-d975b6c671a1']);
        $user->givePermission('posts:create');

        self::assertTrue(Authorization::for($user)->can('posts:create'));
        self::assertTrue(\Illuminate\Support\Facades\Gate::forUser($user)->allows('posts:create'));
    }

    /**
     * authorize() fires AuthorizationFailed and DecisionEvaluated before
     * throwing.
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
        $user = StubIdentity::create(['id' => '2fb407a0-1304-45b9-8c18-80b048cc3196']);

        $override = EvaluationPolicy::fromArray([
            'name'       => 'ad-hoc',
            'statements' => [['effect' => 'allow', 'actions' => ['ad:hoc']]],
        ]);

        $decision = Authorization::for($user)->withPolicies([$override])->evaluate('ad:hoc');

        self::assertTrue($decision->allowed);
        self::assertSame(DecisionReason::EXPLICIT_ALLOW, $decision->reason);
    }

    /**
     * Spatie aliases mirror the canonical trait methods.
     *
     * @return void
     */
    public function testSpatieAliasesMirrorCanonical(): void
    {
        Permission::create(['id' => 'aefe96cf-321f-4555-8ab0-0abd787416d8', 'name' => 'spatie:do', 'guard_name' => 'web']);
        Role::create(['id' => 'e50e9f4f-2d91-41ec-8466-4af39743951b', 'name' => 'spatie-role', 'guard_name' => 'web']);

        $user = StubIdentity::create(['id' => 'ee7ee7dc-2f40-46b6-8cc2-d7e13e2a8825']);

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
     * `Authorization::currentPrincipal()` returns the principal the resolver
     * currently reports — the single accessor every surface (middleware, Blade,
     * future consumers) delegates to.
     *
     * @return void
     */
    public function testCurrentPrincipalExposesTheResolvedPrincipal(): void
    {
        self::assertNull(Authorization::currentPrincipal());

        $user = StubIdentity::create(['id' => '1bf39684-eb97-4b99-8898-2971c1e19c35']);

        self::assertSame($user, Authorization::for($user)->currentPrincipal());
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

        return \array_values($values); // @phpstan-ignore arrayValues.list (numeric-indexed list coerce)
    }
}
