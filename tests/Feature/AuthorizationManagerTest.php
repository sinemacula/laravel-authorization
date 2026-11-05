<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Gate;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Concerns\HasPermissions;
use SineMacula\Laravel\Authorization\Concerns\HasPolicies;
use SineMacula\Laravel\Authorization\Concerns\HasRoles;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect;
use SineMacula\Laravel\Authorization\Evaluation\Enums\TraceDecision;
use SineMacula\Laravel\Authorization\Evaluation\EvaluationResult;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Evaluation\Statement;
use SineMacula\Laravel\Authorization\Events\AuthorizationFailed;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Authorization\Events\Identity\PermissionGranted as IdentityPermissionGranted;
use SineMacula\Laravel\Authorization\Events\Identity\PermissionRevoked as IdentityPermissionRevoked;
use SineMacula\Laravel\Authorization\Events\Identity\PolicyAttached as IdentityPolicyAttached;
use SineMacula\Laravel\Authorization\Events\Identity\PolicyDetached as IdentityPolicyDetached;
use SineMacula\Laravel\Authorization\Events\Identity\RoleAssigned as IdentityRoleAssigned;
use SineMacula\Laravel\Authorization\Events\Identity\RoleRevoked as IdentityRoleRevoked;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Exceptions\UnknownPermissionException;
use SineMacula\Laravel\Authorization\Exceptions\UnknownRoleException;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use Tests\Feature\Stubs\AuthenticatableIdentity;
use Tests\Feature\Stubs\Enums\IntBackedPermissionEnum;
use Tests\Feature\Stubs\Enums\PermissionEnum;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubSubjectResolver;
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
     * Laravel's handler renders a denial from `authorize()` as a `403` whose
     * body is the translated message alone, naming neither the action nor the
     * resource.
     *
     * @return void
     */
    public function testDenialRendersAsForbidden(): void
    {
        $this->app->make(ConfigRepository::class)->set('app.debug', false); // @phpstan-ignore method.nonObject

        /** @var \Illuminate\Routing\Router $router */
        $router = $this->app->make('router'); // @phpstan-ignore method.nonObject
        $router->get('/authorize', static function (): void {
            Authorization::authorize('posts:delete', 'arn:posts:1');
        });

        $this->getJson('/authorize')
            ->assertForbidden()
            ->assertExactJson(['message' => 'This action is unauthorized.']);
    }

    /**
     * RBAC allow via direct permission.
     *
     * @return void
     */
    public function testDirectPermissionGrantsAllow(): void
    {
        Permission::create(['id' => '7a5c8f67-eba9-492b-8a42-a49ec654b516', 'name' => 'posts:create', 'guard' => 'web']);

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
        $role       = Role::create(['id' => '73b70528-9653-431a-8837-48847b3ee826', 'name' => 'editor', 'guard' => 'web']);
        $permission = Permission::create(['id' => 'de7fb420-9d52-4329-8c2e-eb88b1cdc77c', 'name' => 'posts:update', 'guard' => 'web']);
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
        $role       = Role::create(['id' => '5596d2e7-ed0e-4a25-8b13-556e36de93e9', 'name' => 'admin', 'guard' => 'web']);
        $permission = Permission::create(['id' => 'cad09583-86ca-42b3-89fc-9dde9a3020b6', 'name' => 'posts:delete', 'guard' => 'web']);
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
        $role       = Role::create(['id' => '892c12f1-70f5-4a5d-83c0-946bfd611a71', 'name' => 'admin', 'guard' => 'web']);
        $permission = Permission::create(['id' => '6d4ddc84-e926-4fa9-819b-716c3a423654', 'name' => 'posts:delete', 'guard' => 'web']);
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

        Role::create(['id' => '9e294583-8b87-4fea-86ba-15de1a2f73ed', 'name' => 'writer', 'guard' => 'web']);
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
        Role::create(['id' => '1ea0f4c9-a06c-4c53-86a7-4807d569a51c', 'name' => 'a', 'guard' => 'web']);
        Role::create(['id' => 'b4a0f6f6-1195-48e2-8020-eb84a104928b', 'name' => 'b', 'guard' => 'web']);
        Role::create(['id' => '4948f001-2d70-46c7-8b17-687e7a55479d', 'name' => 'c', 'guard' => 'web']);

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

        Permission::create(['id' => '7b2cc2e2-1f29-4467-8a74-844bedaac2d2', 'name' => 'ev:do', 'guard' => 'web']);
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
        $config = $this->app->make('config'); // @phpstan-ignore method.nonObject
        $config->set('authorization.permission_enums', [PermissionEnum::class]);

        (new AuthorizationServiceProvider($this->app))->boot();

        Permission::create(['id' => '70be15aa-1ce5-4c1f-87a5-1c8e91a02587', 'name' => 'posts:create', 'guard' => 'web']);

        $user = StubIdentity::create(['id' => 'd004aa1d-ff0c-4776-8a4c-d975b6c671a1']);
        $user->givePermission('posts:create');

        self::assertTrue(Authorization::for($user)->can('posts:create'));
        self::assertTrue(Gate::forUser($user)->allows('posts:create'));
    }

    /**
     * `effectivePermissions()` keys its map by each case's value, the
     * permission name.
     *
     * @return void
     */
    public function testEffectivePermissionsAreKeyedByCaseValue(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make('config'); // @phpstan-ignore method.nonObject
        $config->set('authorization.permission_enums', [PermissionEnum::class]);

        Permission::create(['id' => '0d4a3f0e-2f5e-4c39-9b0b-4f8ab2a1c5d1', 'name' => PermissionEnum::POSTS_CREATE->value, 'guard' => 'web']);

        $user = StubIdentity::create(['id' => '7c3e9f12-55a4-4b8e-b0a7-2d1c6e8f9a03']);
        $user->givePermission(PermissionEnum::POSTS_CREATE->value);

        self::assertSame(
            [PermissionEnum::POSTS_CREATE->value => true, PermissionEnum::POSTS_DELETE->value => false],
            Authorization::for($user)->effectivePermissions(),
        );
    }

    /**
     * `effectivePermissions()` reads the configured enums at call time, after
     * the boot validation, so it skips an enum not backed by strings rather
     * than fail with a TypeError mid-request.
     *
     * @return void
     */
    public function testEffectivePermissionsSkipAnEnumNotBackedByStrings(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make('config'); // @phpstan-ignore method.nonObject
        $config->set('authorization.permission_enums', [IntBackedPermissionEnum::class, PermissionEnum::class]);

        $user = StubIdentity::create(['id' => '5b0f6c1e-8d2a-4f3b-9e7c-1a4d2c6b8e90']);

        self::assertSame(
            [PermissionEnum::POSTS_CREATE->value => false, PermissionEnum::POSTS_DELETE->value => false],
            Authorization::for($user)->effectivePermissions(),
        );
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
            $this->app->make(AuthorizationManager::class)->authorize('nope'); // @phpstan-ignore method.nonObject
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
     * An invalid statement supplied through `withPolicies()` denies the check
     * with the `invalid_policy` reason even though the principal holds the
     * permission: RBAC never overrides an invalid policy.
     *
     * @return void
     */
    public function testInvalidOverridePolicyDeniesDespiteHeldPermission(): void
    {
        Permission::create(['id' => '0f1c8c43-5a59-4f4e-9d1f-3b2b9a8f6e01', 'name' => 'posts:create', 'guard' => 'web']);

        $user = StubIdentity::create(['id' => '6c0b5d4e-2f7a-4e43-8b6e-1d9c3a7f2e02']);
        $user->givePermission('posts:create');

        $invalid = new EvaluationPolicy(
            name: 'broken-override',
            statements: [
                new Statement(
                    effect: PolicyEffect::ALLOW,
                    actions: ['posts:create'],
                    conditions: ['tenant' => ['nope' => 'org-1']],
                ),
            ],
        );

        $decision = Authorization::for($user)->withPolicies([$invalid])->evaluate('posts:create', null, ['tenant' => 'org-1']);

        self::assertFalse($decision->allowed);
        self::assertSame(DecisionReason::INVALID_POLICY, $decision->reason);
        self::assertNull($decision->matchedStatement);
        self::assertSame([
            [
                'policy'          => 'broken-override',
                'statement_index' => 0,
                'decision'        => TraceDecision::MATCHED,
                'reason'          => 'invalid statement: condition \'tenant\' has an unknown operator \'nope\'',
            ],
        ], $decision->trace);
        self::assertFalse(Authorization::for($user)->withPolicies([$invalid])->can('posts:create', null, ['tenant' => 'org-1']));
    }

    /**
     * A stored policy row whose document cannot be read denies the check with
     * the `invalid_policy` reason even though the principal holds the
     * permission.
     *
     * @return void
     */
    public function testMalformedStoredPolicyDeniesDespiteHeldPermission(): void
    {
        Permission::create(['id' => '3e8a1f2b-7c4d-4b9e-a6f0-5d2c8e1b7a03', 'name' => 'posts:create', 'guard' => 'web']);

        $user = StubIdentity::create(['id' => '9a7e3c1d-4b2f-4e8a-b5c6-0f1e2d3c4b04']);
        $user->givePermission('posts:create');

        DB::table('policies')->insert([
            'id'         => 'b4c3d2e1-f0a9-4b8c-9d7e-6f5a4b3c2d05',
            'name'       => 'stored-broken',
            'document'   => \json_encode(['statements' => [['effect' => 'allow', 'actions' => ['posts:create'], 'unexpected' => true]]]),
            'created_at' => now(),
            'updated_at' => now(),
        ]);
        DB::table('authorizable_policies')->insert([
            'policy_id'         => 'b4c3d2e1-f0a9-4b8c-9d7e-6f5a4b3c2d05',
            'authorizable_type' => $user->getMorphClass(),
            'authorizable_id'   => '9a7e3c1d-4b2f-4e8a-b5c6-0f1e2d3c4b04',
        ]);

        $decision = Authorization::for($user)->evaluate('posts:create');

        self::assertFalse($decision->allowed);
        self::assertSame(DecisionReason::INVALID_POLICY, $decision->reason);
        self::assertNull($decision->matchedStatement);
        self::assertSame([], $decision->trace);
    }

    /**
     * RBAC still applies when no policy decides the check: an implicit deny
     * falls back to the held permission and keeps the evaluator's trace.
     *
     * @return void
     */
    public function testHeldPermissionAppliesOnImplicitDeny(): void
    {
        Permission::create(['id' => '5d4c3b2a-1f0e-4d9c-8b7a-6e5f4d3c2b06', 'name' => 'posts:create', 'guard' => 'web']);

        $user = StubIdentity::create(['id' => '7f6e5d4c-3b2a-4190-8f7e-6d5c4b3a2f07']);
        $user->givePermission('posts:create');

        $unrelated = EvaluationPolicy::fromArray([
            'name'       => 'unrelated',
            'statements' => [['effect' => 'allow', 'actions' => ['posts:delete']]],
        ]);

        $decision = Authorization::for($user)->withPolicies([$unrelated])->evaluate('posts:create');

        self::assertTrue($decision->allowed);
        self::assertSame(DecisionReason::RBAC_ALLOW, $decision->reason);
        self::assertSame([
            [
                'policy'          => 'unrelated',
                'statement_index' => 0,
                'decision'        => TraceDecision::SKIPPED,
                'reason'          => 'action/resource did not match',
            ],
        ], $decision->trace);
    }

    /**
     * An allow whose conditions cannot be decided is skipped, so the check
     * falls through to RBAC; a deny whose conditions cannot be decided applies
     * and RBAC does not override it.
     *
     * @return void
     */
    public function testUndecidableConditionsSkipAllowButApplyDeny(): void
    {
        Permission::create(['id' => '2a3b4c5d-6e7f-4a8b-9c0d-1e2f3a4b5c08', 'name' => 'posts:create', 'guard' => 'web']);

        $user = StubIdentity::create(['id' => '8e9f0a1b-2c3d-4e5f-a6b7-c8d9e0f1a209']);
        $user->givePermission('posts:create');

        $allow = EvaluationPolicy::fromArray([
            'name'       => 'conditional-allow',
            'statements' => [['effect' => 'allow', 'actions' => ['posts:create'], 'conditions' => ['tenant' => ['eq' => 'org-1']]]],
        ]);
        $deny = EvaluationPolicy::fromArray([
            'name'       => 'conditional-deny',
            'statements' => [['effect' => 'deny', 'actions' => ['posts:create'], 'conditions' => ['tenant' => ['eq' => 'org-1']]]],
        ]);

        $skipped = Authorization::for($user)->withPolicies([$allow])->evaluate('posts:create');

        self::assertTrue($skipped->allowed);
        self::assertSame(DecisionReason::RBAC_ALLOW, $skipped->reason);
        self::assertSame('could not be decided: key \'tenant\' is missing from the context', $skipped->trace[0]['reason'] ?? null);

        $denied = Authorization::for($user)->withPolicies([$deny])->evaluate('posts:create');

        self::assertFalse($denied->allowed);
        self::assertSame(DecisionReason::EXPLICIT_DENY, $denied->reason);
        self::assertSame('explicit deny: key \'tenant\' is missing from the context', $denied->trace[0]['reason'] ?? null);
    }

    /**
     * `refuseUnidentifiedResource()` denies the resolved principal implicitly
     * without consulting RBAC, records the denial as the last decision and
     * dispatches exactly one decision event without a resource.
     *
     * @return void
     */
    public function testRefuseUnidentifiedResourceDeniesTheResolvedPrincipal(): void
    {
        Permission::create(['id' => '4c5d6e7f-8a9b-4c0d-9e1f-2a3b4c5d6e10', 'name' => 'posts:create', 'guard' => 'web']);

        $user = StubIdentity::create(['id' => '5d6e7f8a-9b0c-4d1e-8f2a-3b4c5d6e7f11']);
        $user->givePermission('posts:create');

        $this->resolvePrincipalAs($user);

        Event::fake();

        $result = Authorization::refuseUnidentifiedResource('posts:create', ['tenant' => 'org-1']);

        self::assertFalse($result->allowed);
        self::assertSame(DecisionReason::IMPLICIT_DENY, $result->reason);
        self::assertNull($result->matchedStatement);
        self::assertSame([], $result->trace);
        self::assertSame($result, Authorization::lastDecision());

        self::assertSoleDecisionEvent($user, ['tenant' => 'org-1'], $result);
    }

    /**
     * `refuseUnidentifiedResource()` on a `for()` scope denies that principal
     * implicitly without consulting RBAC, records the denial as the last
     * decision and dispatches exactly one decision event without a resource.
     *
     * @return void
     */
    public function testRefuseUnidentifiedResourceDeniesTheScopedPrincipal(): void
    {
        Permission::create(['id' => '6e7f8a9b-0c1d-4e2f-9a3b-4c5d6e7f8a12', 'name' => 'posts:create', 'guard' => 'web']);

        $user = StubIdentity::create(['id' => '7f8a9b0c-1d2e-4f3a-8b4c-5d6e7f8a9b13']);
        $user->givePermission('posts:create');

        Event::fake();

        $result = Authorization::for($user)->refuseUnidentifiedResource('posts:create', ['tenant' => 'org-2']);

        self::assertFalse($result->allowed);
        self::assertSame(DecisionReason::IMPLICIT_DENY, $result->reason);
        self::assertNull($result->matchedStatement);
        self::assertSame([], $result->trace);
        self::assertSame($result, Authorization::lastDecision());

        self::assertSoleDecisionEvent($user, ['tenant' => 'org-2'], $result);
    }

    /**
     * Spatie aliases mirror the canonical trait methods.
     *
     * @return void
     */
    public function testSpatieAliasesMirrorCanonical(): void
    {
        Permission::create(['id' => 'aefe96cf-321f-4555-8ab0-0abd787416d8', 'name' => 'spatie:do', 'guard' => 'web']);
        Role::create(['id' => 'e50e9f4f-2d91-41ec-8466-4af39743951b', 'name' => 'spatie-role', 'guard' => 'web']);

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
     * `Authorization::currentSubject()` returns the subject the resolver
     * currently reports — the single accessor every surface (middleware, Blade,
     * future consumers) delegates to — or the one `for()` names.
     *
     * @return void
     */
    public function testCurrentSubjectExposesTheResolvedSubject(): void
    {
        self::assertNull(Authorization::currentSubject());

        $user = StubIdentity::create(['id' => '1bf39684-eb97-4b99-8898-2971c1e19c35']);

        self::assertSame($user, Authorization::for($user)->currentSubject()?->subject);
    }

    /**
     * With the shipped resolver and no user signed in, there is no subject and
     * every check denies.
     *
     * @return void
     */
    public function testNoSignedInUserMeansNoSubjectAndADenial(): void
    {
        Permission::create(['name' => 'posts:create', 'guard' => 'web']);

        $user = AuthenticatableIdentity::create(['id' => 'c7d4e2a8-5b1f-4c3e-8d9a-0f1e2d3c4b5a']);
        $user->givePermission('posts:create');

        self::assertNull(Authorization::currentSubject());
        self::assertFalse(Authorization::can('posts:create'));
    }

    /**
     * With the shipped resolver, the user Laravel signed in is the subject and
     * its identity, on the default guard, which is also the application, and
     * checks decide about that user.
     *
     * @return void
     */
    public function testTheSignedInUserIsTheSubject(): void
    {
        Permission::create(['name' => 'posts:create', 'guard' => 'web']);

        $user = AuthenticatableIdentity::create(['id' => '2f9e8d7c-6b5a-4c3d-9e1f-a0b1c2d3e4f5']);
        $user->givePermission('posts:create');

        $this->actingAs($user);

        $subject = Authorization::currentSubject();

        self::assertNotNull($subject);
        self::assertSame($user, $subject->subject);
        self::assertSame($user, $subject->identity);
        self::assertNull($subject->tenant);
        self::assertSame('web', $subject->guard);
        self::assertSame('web', $subject->application);
        self::assertTrue(Authorization::can('posts:create'));
        self::assertFalse(Authorization::can('posts:delete'));
    }

    /**
     * Assert that exactly one decision event was dispatched, for the check of
     * `posts:create` without a resource, carrying the supplied principal,
     * context and result, and that no failure event was dispatched.
     *
     * @param  object  $principal
     * @param  array<string, mixed>  $context
     * @param  \SineMacula\Laravel\Authorization\Evaluation\EvaluationResult  $result
     * @return void
     */
    private static function assertSoleDecisionEvent(object $principal, array $context, EvaluationResult $result): void
    {
        $events = \array_values(
            Event::dispatched(DecisionEvaluated::class)
                ->map(static fn (array $arguments): DecisionEvaluated => $arguments[0])
                ->all(),
        );

        self::assertCount(1, $events);
        self::assertSame($principal, $events[0]->principal);
        self::assertSame('posts:create', $events[0]->action);
        self::assertNull($events[0]->resource);
        self::assertSame($context, $events[0]->context);
        self::assertSame($result, $events[0]->result);
        Event::assertNotDispatched(AuthorizationFailed::class);
    }

    /**
     * Swap the subject resolver for one that returns the supplied authorizable
     * and refresh the manager so the next facade call picks it up.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $user
     * @return void
     */
    private function resolvePrincipalAs(StubIdentity $user): void
    {
        $resolver = new StubSubjectResolver($user);

        $this->app->instance(SubjectResolver::class, $resolver); // @phpstan-ignore method.nonObject
        $this->app->forgetInstance('authorization'); // @phpstan-ignore method.nonObject
        $this->app->forgetInstance(AuthorizationManager::class); // @phpstan-ignore method.nonObject
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

        return \array_values($values); // @phpstan-ignore arrayValues.list
    }
}
