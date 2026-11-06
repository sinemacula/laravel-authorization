<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Support\Carbon;
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
use SineMacula\Laravel\Authorization\Context\CheckContextFactory;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationRequirementChecker;
use SineMacula\Laravel\Authorization\Contracts\ResourceTenantResolver;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Evaluation\AuthenticationRequirement;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionStage;
use SineMacula\Laravel\Authorization\Evaluation\Enums\PolicyEffect;
use SineMacula\Laravel\Authorization\Evaluation\Enums\TraceOutcome;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Evaluation\RequirementFreshness;
use SineMacula\Laravel\Authorization\Evaluation\RequirementResult;
use SineMacula\Laravel\Authorization\Evaluation\Statement;
use SineMacula\Laravel\Authorization\Evaluation\StatementReference;
use SineMacula\Laravel\Authorization\Evaluation\TraceEntry;
use SineMacula\Laravel\Authorization\Evaluation\UnmetRequirement;
use SineMacula\Laravel\Authorization\Events\AuthorizationFailed;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Authorization\Events\Identity\PermissionGranted as IdentityPermissionGranted;
use SineMacula\Laravel\Authorization\Events\Identity\PermissionRevoked as IdentityPermissionRevoked;
use SineMacula\Laravel\Authorization\Events\Identity\PolicyAttached as IdentityPolicyAttached;
use SineMacula\Laravel\Authorization\Events\Identity\PolicyDetached as IdentityPolicyDetached;
use SineMacula\Laravel\Authorization\Events\Identity\RoleAssigned as IdentityRoleAssigned;
use SineMacula\Laravel\Authorization\Events\Identity\RoleRevoked as IdentityRoleRevoked;
use SineMacula\Laravel\Authorization\Exceptions\AttributeProviderFailed;
use SineMacula\Laravel\Authorization\Exceptions\AuthorizationException;
use SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException;
use SineMacula\Laravel\Authorization\Exceptions\UnknownPermissionException;
use SineMacula\Laravel\Authorization\Exceptions\UnknownRoleException;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResolvedTenant;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use Tests\Feature\Stubs\AuthenticatableIdentity;
use Tests\Feature\Stubs\Enums\IntBackedPermissionEnum;
use Tests\Feature\Stubs\Enums\PermissionEnum;
use Tests\Feature\Stubs\FailingResourceAttributes;
use Tests\Feature\Stubs\FixedResourceTenantResolver;
use Tests\Feature\Stubs\FixedSubjectResolver;
use Tests\Feature\Stubs\PlanContextSource;
use Tests\Feature\Stubs\RecordingResourceAttributes;
use Tests\Feature\Stubs\RecordingSubjectAttributes;
use Tests\Feature\Stubs\ReservedContextSource;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubRequirementChecker;
use Tests\Feature\Stubs\StubSecondIdentity;
use Tests\Feature\Stubs\StubSubjectResolver;
use Tests\Feature\Stubs\StubTenant;
use Tests\Feature\Stubs\StubTenantTree;
use Tests\Feature\Stubs\SuspendableIdentity;
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
     * A role granted in an organisation allows in an account below it and not
     * in one beside it; once the account moves away and the tree change is
     * reported, by model or by reference, the cached grant no longer reaches
     * it, and once it moves back, reaches it again.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGrantReachesTheTenantsBelowItUntilTheTreeChanges(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app?->make(ConfigRepository::class);
        $config->set('authorization.cache.store', 'array');

        (new AuthorizationServiceProvider($this->app))->register(); // @phpstan-ignore argument.type

        [$org, $account, $sibling] = \array_map(static fn (string $id): StubTenant => StubTenant::query()->create(['id' => $id, 'name' => $id]), ['org', 'account', 'sibling']);
        $tree                      = (new StubTenantTree)->put(Reference::of($account), Reference::of($org));
        $user                      = StubIdentity::create(['id' => 'user-1']);

        $this->app?->instance(TenantTree::class, $tree);

        Role::create(['name' => 'editor'])->givePermission(Permission::create(['name' => 'posts:edit']));
        $user->assignRole('editor', null, $org);

        $in = function (StubTenant $tenant) use ($user): bool {
            $this->app?->instance(SubjectResolver::class, new StubSubjectResolver($user, $tenant));
            $this->app?->forgetInstance(ResolvedTenant::class);

            return Authorization::can('posts:edit');
        };

        self::assertTrue($in($account));
        self::assertFalse($in($sibling));

        $tree->put(Reference::of($account), Reference::of($sibling));

        self::assertTrue($in($account));

        Authorization::treeChanged($account);

        self::assertFalse($in($account));

        // Within one request, the report alone reads the ancestors again, and a
        // reference reports a tenant as its model does.
        $tree->put(Reference::of($account), Reference::of($org));

        self::assertFalse(Authorization::can('posts:edit'));

        Authorization::treeChanged(Reference::of($account));

        self::assertTrue(Authorization::can('posts:edit'));
    }

    /**
     * A subject that is inactive, or whose identity is, is denied everything as
     * `subject_inactive`, before any grant or policy is read.
     *
     * @return void
     */
    public function testAnInactiveSubjectOrIdentityIsDeniedEverything(): void
    {
        $principal = SuspendableIdentity::create(['id' => 'account-1']);
        $identity  = SuspendableIdentity::create(['id' => 'person-1']);

        $principal->givePermission(Permission::create(['name' => 'posts:edit']));
        $this->app?->instance(SubjectResolver::class, new FixedSubjectResolver(new Subject($principal, $identity)));

        $manager = $this->app?->make(AuthorizationManager::class);
        self::assertNotNull($manager);
        self::assertTrue($manager->can('posts:edit'));

        $identity->suspended = true;

        self::assertSame(DecisionReason::SUBJECT_INACTIVE, $manager->check('posts:edit')->reason);

        $identity->suspended  = false;
        $principal->suspended = true;

        $decision = $manager->check('posts:edit');

        self::assertFalse($decision->isAllowed());
        self::assertSame(DecisionReason::SUBJECT_INACTIVE, $decision->reason);
        self::assertSame(DecisionStage::SUBJECT, $decision->stage);
        self::assertSame([], $decision->trace);
    }

    /**
     * A decision about a principal counts its identity's grants and policies
     * too: a permission the identity holds allows, and a deny the identity
     * carries wins over the principal's grant.
     *
     * @return void
     */
    public function testTheIdentitysGrantsAndPoliciesCount(): void
    {
        $principal = SuspendableIdentity::create(['id' => 'account-1']);
        $identity  = StubSecondIdentity::create(['id' => 'person-1']);

        $principal->givePermission(Permission::create(['name' => 'posts:edit']));
        $identity->givePermission(Permission::create(['name' => 'admin:read']));
        $identity->attachPolicy(Policy::create(['name' => 'no-editing', 'document' => ['version' => 1, 'statements' => [['effect' => 'deny', 'actions' => ['posts:edit']]]]]));

        $this->app?->instance(SubjectResolver::class, new FixedSubjectResolver(new Subject($principal, $identity)));

        $manager = $this->app?->make(AuthorizationManager::class);
        self::assertNotNull($manager);

        $held = $manager->check('admin:read');

        self::assertTrue($held->isAllowed());
        self::assertNull($held->reason);
        self::assertSame(DecisionStage::ALLOW, $held->stage);
        self::assertSame(DecisionReason::EXPLICIT_DENY, $manager->check('posts:edit')->reason);
    }

    /**
     * Anonymous resolver yields a `subject_unresolved` denial at the subject
     * stage on can() and check(), and throws from authorize().
     *
     * @return void
     */
    public function testAnonymousPrincipalIsImplicitlyDenied(): void
    {
        self::assertFalse(Authorization::can('posts:create'));

        $decision = Authorization::check('posts:create');

        self::assertSame(DecisionReason::SUBJECT_UNRESOLVED, $decision->reason);
        self::assertSame(DecisionStage::SUBJECT, $decision->stage);

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
     * RBAC allow via direct permission: an allow at the allow stage with no
     * reason and no statement, its trace ending with the permission held.
     *
     * @return void
     */
    public function testDirectPermissionGrantsAllow(): void
    {
        Permission::create(['id' => '7a5c8f67-eba9-492b-8a42-a49ec654b516', 'name' => 'posts:create', 'guard' => 'web']);

        $user = StubIdentity::create(['id' => '1705066a-b10d-4f4a-8aba-73758a3a381a']);
        $user->givePermission('posts:create');

        $decision = Authorization::for($user)->check('posts:create');
        self::assertTrue($decision->isAllowed());
        self::assertNull($decision->reason);
        self::assertSame(DecisionStage::ALLOW, $decision->stage);
        self::assertSame([], $decision->statements);
        self::assertEquals([new TraceEntry(DecisionStage::ALLOW, TraceOutcome::HELD)], $decision->trace);
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

        $decision = Authorization::for($user)->check('posts:delete');
        self::assertFalse($decision->isAllowed());
        self::assertSame(DecisionReason::EXPLICIT_DENY, $decision->reason);
        self::assertSame(DecisionStage::DENY, $decision->stage);
        self::assertEquals([new StatementReference('deny-posts-delete', 0, $policy->id)], $decision->statements);
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
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException
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
     * withPolicies scope overrides principal-attached policies: its allow
     * statement decides the check at the allow stage.
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

        $decision = Authorization::for($user)->withPolicies([$override])->check('ad:hoc');

        self::assertTrue($decision->isAllowed());
        self::assertNull($decision->reason);
        self::assertSame(DecisionStage::ALLOW, $decision->stage);
        self::assertEquals([new StatementReference('ad-hoc', 0)], $decision->statements);
    }

    /**
     * An invalid allow statement supplied through `withPolicies()` denies the
     * check with the `invalid_policy` reason at the allow stage even though the
     * principal holds the permission: RBAC never overrides an invalid policy.
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
                    conditions: ['eq' => ['input.tenant' => ['org-1']]],
                ),
            ],
        );

        $decision = Authorization::for($user)->withPolicies([$invalid])->check('posts:create', null, ['tenant' => 'org-1']);

        self::assertFalse($decision->isAllowed());
        self::assertSame(DecisionReason::INVALID_POLICY, $decision->reason);
        self::assertSame(DecisionStage::ALLOW, $decision->stage);
        self::assertEquals([new StatementReference('broken-override', 0)], $decision->statements);
        self::assertEquals([
            new TraceEntry(DecisionStage::ALLOW, TraceOutcome::INVALID, new StatementReference('broken-override', 0), ['input.tenant' => false]),
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

        $decision = Authorization::for($user)->check('posts:create');

        self::assertFalse($decision->isAllowed());
        self::assertSame(DecisionReason::INVALID_POLICY, $decision->reason);
        self::assertSame(DecisionStage::DENY, $decision->stage);
        self::assertSame([], $decision->statements);
        self::assertSame([], $decision->trace);
    }

    /**
     * RBAC still applies when no policy decides the check: a `no_match` denial
     * falls back to the held permission, allowing at the allow stage, and keeps
     * the evaluator's trace with the permission step after it.
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

        $decision = Authorization::for($user)->withPolicies([$unrelated])->check('posts:create');

        self::assertTrue($decision->isAllowed());
        self::assertNull($decision->reason);
        self::assertSame(DecisionStage::ALLOW, $decision->stage);
        self::assertSame([], $decision->statements);
        self::assertEquals([
            new TraceEntry(DecisionStage::ALLOW, TraceOutcome::NOT_APPLICABLE, new StatementReference('unrelated', 0)),
            new TraceEntry(DecisionStage::ALLOW, TraceOutcome::HELD),
        ], $decision->trace);
    }

    /**
     * An allow whose conditions cannot be decided allows nothing, so the check
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
            'statements' => [['effect' => 'allow', 'actions' => ['posts:create'], 'conditions' => ['eq' => ['input.tenant' => 'org-1']]]],
        ]);
        $deny = EvaluationPolicy::fromArray([
            'name'       => 'conditional-deny',
            'statements' => [['effect' => 'deny', 'actions' => ['posts:create'], 'conditions' => ['eq' => ['input.tenant' => 'org-1']]]],
        ]);

        $skipped = Authorization::for($user)->withPolicies([$allow])->check('posts:create');

        self::assertTrue($skipped->isAllowed());
        self::assertNull($skipped->reason);
        self::assertSame(DecisionStage::ALLOW, $skipped->stage);
        self::assertSame([], $skipped->statements);
        self::assertEquals([
            new TraceEntry(DecisionStage::ALLOW, TraceOutcome::UNDECIDABLE, new StatementReference('conditional-allow', 0), ['input.tenant' => false]),
            new TraceEntry(DecisionStage::ALLOW, TraceOutcome::HELD),
        ], $skipped->trace);

        $denied = Authorization::for($user)->withPolicies([$deny])->check('posts:create');

        self::assertFalse($denied->isAllowed());
        self::assertSame(DecisionReason::EXPLICIT_DENY, $denied->reason);
        self::assertSame(DecisionStage::DENY, $denied->stage);
        self::assertEquals([new StatementReference('conditional-deny', 0)], $denied->statements);
        self::assertEquals([
            new TraceEntry(DecisionStage::DENY, TraceOutcome::UNDECIDABLE, new StatementReference('conditional-deny', 0), ['input.tenant' => false]),
        ], $denied->trace);
    }

    /**
     * `check()` on an unsaved model, which cannot be identified, denies the
     * resolved principal as `resource_unresolved` at the resource stage without
     * consulting RBAC, records the denial as the last decision and dispatches
     * exactly one decision event without a resource.
     *
     * @return void
     */
    public function testCheckDeniesAnUnidentifiableResourceForTheResolvedPrincipal(): void
    {
        Permission::create(['id' => '4c5d6e7f-8a9b-4c0d-9e1f-2a3b4c5d6e10', 'name' => 'posts:create', 'guard' => 'web']);

        $user = StubIdentity::create(['id' => '5d6e7f8a-9b0c-4d1e-8f2a-3b4c5d6e7f11']);
        $user->givePermission('posts:create');

        $this->resolvePrincipalAs($user);

        Event::fake();

        $decision = Authorization::check('posts:create', new StubIdentity, ['tenant' => 'org-1']);

        self::assertFalse($decision->isAllowed());
        self::assertSame(DecisionReason::RESOURCE_UNRESOLVED, $decision->reason);
        self::assertSame(DecisionStage::RESOURCE, $decision->stage);
        self::assertSame([], $decision->statements);
        self::assertSame([], $decision->trace);
        self::assertSame($decision, Authorization::lastDecision());

        self::assertSoleDecisionEvent($user, ['tenant' => 'org-1'], $decision);
    }

    /**
     * `check()` on a `for()` scope with a number, which cannot be identified,
     * denies that principal as `resource_unresolved` at the resource stage
     * without consulting RBAC, records the denial as the last decision and
     * dispatches exactly one decision event without a resource.
     *
     * @return void
     */
    public function testCheckDeniesAnUnidentifiableResourceForTheScopedPrincipal(): void
    {
        Permission::create(['id' => '6e7f8a9b-0c1d-4e2f-9a3b-4c5d6e7f8a12', 'name' => 'posts:create', 'guard' => 'web']);

        $user = StubIdentity::create(['id' => '7f8a9b0c-1d2e-4f3a-8b4c-5d6e7f8a9b13']);
        $user->givePermission('posts:create');

        Event::fake();

        $decision = Authorization::for($user)->check('posts:create', 42, ['tenant' => 'org-2']);

        self::assertFalse($decision->isAllowed());
        self::assertSame(DecisionReason::RESOURCE_UNRESOLVED, $decision->reason);
        self::assertSame(DecisionStage::RESOURCE, $decision->stage);
        self::assertSame([], $decision->statements);
        self::assertSame([], $decision->trace);
        self::assertSame($decision, Authorization::lastDecision());

        self::assertSoleDecisionEvent($user, ['tenant' => 'org-2'], $decision);
    }

    /**
     * `check()` names a saved model, a pair and a model class to the evaluator
     * as `type:id`, `type:id` and `type:*`, so each is allowed by the one
     * statement written for that identifier and another record of the model's
     * type is not, and each `DecisionEvaluated` carries the identifier string.
     * The model class is another type, since only a pattern that covers every
     * record of a type covers the type alone.
     *
     * @return void
     */
    public function testCheckNamesAModelAPairAndAClassStringByTheirIdentifiers(): void
    {
        $user  = StubIdentity::create(['id' => '8a9b0c1d-2e3f-4a4b-9c5d-6e7f8a9b0c14']);
        $post  = StubIdentity::create(['id' => '9b0c1d2e-3f4a-4b5c-8d6e-7f8a9b0c1d15']);
        $other = StubIdentity::create(['id' => '0c1d2e3f-4a5b-4c6d-9e7f-8a9b0c1d2e16']);

        $postKey  = $post->getKey();
        $otherKey = $other->getKey();

        self::assertIsString($postKey);
        self::assertIsString($otherKey);

        $policy = EvaluationPolicy::fromArray([
            'name'       => 'by-identifier',
            'statements' => [
                ['effect' => 'allow', 'actions' => ['posts:read'], 'resources' => [StubIdentity::class . ':' . $postKey]],
                ['effect' => 'allow', 'actions' => ['posts:read'], 'resources' => ['posts:7']],
                ['effect' => 'allow', 'actions' => ['posts:read'], 'resources' => [StubTenant::class . ':*']],
            ],
        ]);

        Event::fake();

        $scope = Authorization::for($user)->withPolicies([$policy]);

        foreach ([$post, ['posts', 7], StubTenant::class] as $index => $resource) {
            $decision = $scope->check('posts:read', $resource);

            self::assertTrue($decision->isAllowed());
            self::assertEquals([new StatementReference('by-identifier', $index)], $decision->statements);
        }

        $unmatched = $scope->check('posts:read', $other);

        self::assertFalse($unmatched->isAllowed());
        self::assertSame(DecisionReason::NO_MATCH, $unmatched->reason);

        $resources = Event::dispatched(DecisionEvaluated::class)
            ->map(static fn (array $arguments): ?string => $arguments[0]->resource)
            ->values()
            ->all();

        self::assertSame([
            StubIdentity::class . ':' . $postKey,
            'posts:7',
            StubTenant::class . ':*',
            StubIdentity::class . ':' . $otherKey,
        ], $resources);
    }

    /**
     * `authorize()` denied on a pair reports the pair's `type:id` identifier on
     * both the decision event and the failure event.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException
     */
    public function testAuthorizeReportsTheResourceIdentifierWhenDenied(): void
    {
        $user = StubIdentity::create(['id' => '1d2e3f4a-5b6c-4d7e-8f8a-9b0c1d2e3f17']);

        Event::fake();

        try {
            Authorization::for($user)->authorize('posts:delete', ['posts', 7]);

            self::fail('Expected AuthorizationException.');
        } catch (AuthorizationException) {
            // Expected.
        }

        Event::assertDispatched(DecisionEvaluated::class, static fn (DecisionEvaluated $event): bool => $event->resource === 'posts:7');
        Event::assertDispatched(AuthorizationFailed::class, static fn (AuthorizationFailed $event): bool => $event->resource === 'posts:7');
    }

    /**
     * `authorize()` resolves its resource once: denied on a saved model, or on
     * a pair, it asks the bound resource tenant resolver about it exactly once,
     * and the failure event carries the resource's identifier.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException
     */
    public function testAuthorizeResolvesTheResourceOnce(): void
    {
        $user     = StubIdentity::create(['id' => '4a5b6c7d-8e9f-4a0b-9c1d-2e3f4a5b6c20']);
        $model    = StubTenant::create(['id' => 'tenant-a', 'name' => 'Tenant A']);
        $resolver = new FixedResourceTenantResolver;

        $this->app?->instance(ResourceTenantResolver::class, $resolver);

        Event::fake();

        foreach ([$model, ['posts', 7]] as $resource) {
            try {
                Authorization::for($user)->authorize('posts:delete', $resource);

                self::fail('Expected AuthorizationException.');
            } catch (AuthorizationException) {
                // Expected.
            }
        }

        self::assertSame([$model], $resolver->asked);
        self::assertSame([['posts', '7']], $resolver->askedRecords);

        $failed = Event::dispatched(AuthorizationFailed::class)
            ->map(static fn (array $arguments): ?string => $arguments[0]->resource)
            ->values()
            ->all();

        self::assertSame([StubTenant::class . ':tenant-a', 'posts:7'], $failed);
    }

    /**
     * A resource that belongs to a tenant is out of scope when no tenant is
     * active: a principal that does not hold the permission outside every
     * tenant is denied as `tenant_scope` at the tenant stage, before any
     * statement is read, even though a statement allows the action; one that
     * holds it is decided by its grants.
     *
     * @return void
     */
    public function testCheckDeniesATenantOwnedResourceOutsideTheScope(): void
    {
        Permission::create(['id' => '2e3f4a5b-6c7d-4e8f-9a9b-0c1d2e3f4a18', 'name' => 'posts:read', 'guard' => 'web']);

        $user     = StubIdentity::create(['id' => '3f4a5b6c-7d8e-4f9a-8b0c-1d2e3f4a5b19']);
        $resource = ResourceReference::record('posts', '7', new Reference('org', 'org-1'));

        $allowAll = EvaluationPolicy::fromArray([
            'name'       => 'allow-all',
            'statements' => [['effect' => 'allow', 'actions' => ['posts:read']]],
        ]);

        $denied = Authorization::for($user)->withPolicies([$allowAll])->check('posts:read', $resource);

        self::assertFalse($denied->isAllowed());
        self::assertSame(DecisionReason::TENANT_SCOPE, $denied->reason);
        self::assertSame(DecisionStage::TENANT, $denied->stage);
        self::assertSame([], $denied->statements);
        self::assertSame([], $denied->trace);

        $user->givePermission('posts:read');

        $allowed = Authorization::for($user)->check('posts:read', $resource);

        self::assertTrue($allowed->isAllowed());
        self::assertSame(DecisionStage::ALLOW, $allowed->stage);
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
     * every check denies, as `subject_unresolved` at the subject stage even
     * when its resource cannot be identified: the subject stage decides first.
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

        $decision = Authorization::check('posts:create', 42);

        self::assertFalse($decision->isAllowed());
        self::assertSame(DecisionReason::SUBJECT_UNRESOLVED, $decision->reason);
        self::assertSame(DecisionStage::SUBJECT, $decision->stage);

        $this->expectException(AuthorizationException::class);

        Authorization::authorize('posts:create');
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
     * What the caller passes, through every form that adapts the check, is read
     * under `input` alone: `['request' => ['ip' => …]]` supplies
     * `input.request.ip`, never `request.ip`, which outside a routed request is
     * missing.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException
     */
    public function testCallerValuesLandUnderInputAndNeverInTheRequest(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app?->make(ConfigRepository::class);
        $config->set('authorization.permission_enums', [PermissionEnum::class]);

        $user = StubIdentity::create(['id' => 'caller']);

        $user->attachPolicy(Policy::create(['name' => 'caller-values', 'document' => ['statements' => [
            ['effect' => 'allow', 'actions' => ['posts:create'], 'conditions' => ['eq' => ['input.request.ip' => '10.0.0.1']]],
            ['effect' => 'allow', 'actions' => ['posts:delete'], 'conditions' => ['eq' => ['request.ip' => '10.0.0.1']]],
        ]]]));

        $caller  = ['request' => ['ip' => '10.0.0.1']];
        $manager = Authorization::for($user);

        self::assertTrue($manager->can('posts:create', null, $caller));
        self::assertTrue($manager->check('posts:create', null, $caller)->isAllowed());
        self::assertStringContainsString('allow', $manager->explain('posts:create', null, $caller));
        self::assertSame(['posts:create' => true, 'posts:delete' => false], $manager->effectivePermissions($caller));
        self::assertFalse($manager->can('posts:delete', null, $caller));
        self::assertFalse($manager->can('posts:delete', null, ['request.ip' => '10.0.0.1']));

        $manager->authorize('posts:create', null, $caller);

        $this->expectException(AuthorizationException::class);

        $manager->authorize('posts:delete', null, $caller);
    }

    /**
     * The `authentication` namespace is the default guard's name and the
     * signed-in user's key and morph type; with nobody signed in, only the
     * guard is present.
     *
     * @return void
     */
    public function testTheAuthenticationNamespaceIsTheGuardAndItsUser(): void
    {
        $user = AuthenticatableIdentity::create(['id' => 'signed-in']);

        $user->attachPolicy(Policy::create(['name' => 'signed-in', 'document' => ['statements' => [
            ['effect' => 'allow', 'actions' => ['posts:create'], 'conditions' => ['eq' => [
                'authentication.guard'     => 'web',
                'authentication.user_id'   => 'signed-in',
                'authentication.user_type' => $user->getMorphClass(),
            ]]],
            ['effect' => 'allow', 'actions' => ['posts:delete'], 'conditions' => [
                'eq'   => ['authentication.guard' => 'web'],
                'null' => ['authentication.user_id' => true, 'authentication.user_type' => true],
            ]],
        ]]]));

        self::assertFalse(Authorization::for($user)->can('posts:create'));
        self::assertTrue(Authorization::for($user)->can('posts:delete'));

        $this->actingAs($user);

        self::assertTrue(Authorization::for($user)->can('posts:create'));
        self::assertFalse(Authorization::for($user)->can('posts:delete'));
    }

    /**
     * `environment.time` is Laravel's clock in UTC, so a frozen clock decides a
     * time condition and a `${environment.time}` reference alike.
     *
     * @return void
     */
    public function testTheEnvironmentTimeIsTheFrozenClock(): void
    {
        $user = StubIdentity::create(['id' => 'clocked']);

        $user->attachPolicy(Policy::create(['name' => 'office-hours', 'document' => ['statements' => [
            ['effect' => 'allow', 'actions' => ['posts:create'], 'conditions' => ['between' => ['environment.time' => ['2026-03-01T09:00:00Z', '2026-03-01T17:00:00Z']]]],
            ['effect' => 'allow', 'actions' => ['reports:read'], 'resources' => ['report:${environment.time}']],
        ]]]));

        try {
            Carbon::setTestNow(Carbon::parse('2026-03-01 13:30:00', 'Europe/Paris'));

            self::assertTrue(Authorization::for($user)->can('posts:create'));
            self::assertTrue(Authorization::for($user)->can('reports:read', 'report:2026-03-01T12:30:00Z'));
            self::assertFalse(Authorization::for($user)->can('reports:read', 'report:2026-03-01T13:30:00Z'));

            Carbon::setTestNow(Carbon::parse('2026-03-01 18:00:00', 'UTC'));

            self::assertFalse(Authorization::for($user)->can('posts:create'));
        } finally {
            Carbon::setTestNow();
        }
    }

    /**
     * A source `authorization.context.sources` lists adds its namespace, built
     * only for a check whose statements read it, and once for that check, while
     * what the caller passes under the same name stays under `input`.
     *
     * @return void
     */
    public function testAnApplicationSourceAddsANamespace(): void
    {
        $source = new PlanContextSource;

        $this->app?->instance(PlanContextSource::class, $source);

        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app?->make(ConfigRepository::class);
        $config->set('authorization.context.sources', [PlanContextSource::class]);

        $user = StubIdentity::create(['id' => 'subscriber']);

        $user->attachPolicy(Policy::create(['name' => 'pro-only', 'document' => ['statements' => [
            ['effect' => 'allow', 'actions' => ['posts:create'], 'conditions' => ['eq' => ['plan.tier' => 'pro'], 'in' => ['plan.tier' => ['pro', 'team']]]],
            ['effect' => 'allow', 'actions' => ['posts:delete']],
        ]]]));

        self::assertTrue(Authorization::for($user)->can('posts:create', null, ['plan' => ['tier' => 'free']]));
        self::assertSame(1, $source->reads);
        self::assertTrue(Authorization::for($user)->can('posts:delete'));
        self::assertSame(1, $source->reads);

        $source->tier = 'free';

        self::assertFalse(Authorization::for($user)->can('posts:create', null, ['plan' => ['tier' => 'pro']]));
        self::assertSame(2, $source->reads);
    }

    /**
     * A source claiming a reserved namespace is refused when the checks'
     * context is first made, so it can never stand in for the request.
     *
     * @return void
     */
    public function testASourceClaimingAReservedNamespaceIsRefused(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app?->make(ConfigRepository::class);
        $config->set('authorization.context.sources', [ReservedContextSource::class]);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('cannot supply the namespace \'request\'');

        Authorization::can('posts:create');
    }

    /**
     * The `subject` and `resource` namespaces hold the built-in keys of the
     * check's subject and resource, so `${subject.id}` and `${resource.id}`
     * read the subject's key and the record's id, a type alone has no id, and
     * neither is ever read by splitting an opaque identifier.
     *
     * @return void
     */
    public function testTheSubjectAndResourceBuiltInsDecideTheCheck(): void
    {
        $user = StubIdentity::create(['id' => 'self-1']);
        $post = StubIdentity::create(['id' => 'post-1']);
        $type = $user->getMorphClass();

        $policy = EvaluationPolicy::fromArray(['name' => 'built-ins', 'statements' => [
            ['effect' => 'allow', 'actions' => ['users:self'], 'resources' => [$type . ':${subject.id}']],
            ['effect' => 'allow', 'actions' => ['posts:mirror'], 'conditions' => ['eq' => ['input.post_id' => '${resource.id}']]],
            ['effect' => 'allow', 'actions' => ['posts:typed'], 'conditions' => ['eq' => ['resource.type' => 'post', 'subject.type' => $type]]],
        ]]);

        $scope = Authorization::for($user)->withPolicies([$policy]);

        self::assertTrue($scope->can('users:self', $user));
        self::assertFalse($scope->can('users:self', $post));
        self::assertTrue($scope->can('posts:mirror', $post, ['post_id' => 'post-1']));
        self::assertTrue($scope->can('posts:mirror', ['post', 'post-1'], ['post_id' => 'post-1']));
        self::assertFalse($scope->can('posts:mirror', $post, ['post_id' => 'post-2']));
        self::assertFalse($scope->can('posts:mirror', 'post:post-1', ['post_id' => 'post-1']));
        self::assertTrue($scope->can('posts:typed', ['post', '7']));
        self::assertFalse($scope->can('posts:typed', 'post:7'));
        self::assertFalse($scope->can('posts:typed'));
    }

    /**
     * The providers of `authorization.attributes` supply the attributes they
     * declare for the check's subject and record: each is asked at most once
     * for a check, never for one that reads no attribute, and the resource's
     * provider is handed the model the check was given, or none for a pair. A
     * record of a type with no provider has no attributes, a value a provider
     * returns for a key it does not declare is dropped, and the trace holds the
     * keys tested, never their values.
     *
     * @return void
     */
    public function testAttributeProvidersSupplyTheDeclaredAttributes(): void
    {
        $user  = StubIdentity::create(['id' => 'seller-1']);
        $post  = StubIdentity::create(['id' => 'post-2']);
        $type  = $user->getMorphClass();
        $posts = new RecordingResourceAttributes;
        $users = new RecordingSubjectAttributes;

        $this->app?->instance(RecordingResourceAttributes::class, $posts);
        $this->app?->instance(RecordingSubjectAttributes::class, $users);

        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app?->make(ConfigRepository::class);
        $config->set('authorization.attributes', [
            'resources' => [$type => RecordingResourceAttributes::class],
            'subjects'  => [$type => RecordingSubjectAttributes::class],
        ]);

        $policy = EvaluationPolicy::fromArray(['name' => 'attributes', 'statements' => [
            ['effect' => 'allow', 'actions' => ['posts:edit'], 'conditions' => ['eq' => [
                'resource.status'    => 'draft',
                'resource.owner.id'  => '7',
                'subject.department' => 'sales',
            ]]],
            ['effect' => 'allow', 'actions' => ['posts:edit'], 'resources' => ['${resource.type}:${resource.status}']],
            ['effect' => 'allow', 'actions' => ['posts:leak'], 'conditions' => ['eq' => ['resource.secret' => 'classified']]],
            ['effect' => 'allow', 'actions' => ['posts:read']],
        ]]);

        $scope = Authorization::for($user)->withPolicies([$policy]);

        $decision = $scope->check('posts:edit', $post);

        self::assertTrue($decision->isAllowed());
        self::assertSame(['resource.status' => true, 'resource.owner.id' => true, 'subject.department' => true], $decision->trace[0]->conditions);
        self::assertStringNotContainsString('draft', $decision->explain());
        self::assertStringNotContainsString('sales', $decision->explain());
        self::assertTrue($scope->can('posts:edit', [$type, 'post-3']));
        self::assertTrue($scope->can('posts:read', $post));
        self::assertFalse($scope->can('posts:leak', $post));
        self::assertFalse($scope->can('posts:edit', StubTenant::query()->create(['id' => 'tenant-1', 'name' => 'tenant-1'])));
        self::assertFalse($scope->can('posts:edit', $type));

        // One call for each check that read the resource: the model, then none
        // for the pair, then the model again; none for the check reading no
        // attribute, the record of another type or the type alone.
        self::assertSame([$post, null, $post], \array_column($posts->calls, 1));
        self::assertSame(['post-2', 'post-3', 'post-2'], \array_map(static fn (array $call): ?string => $call[0]->id, $posts->calls));
        self::assertSame($user, $users->calls[0]);
    }

    /**
     * A resource attribute provider that throws aborts the check with
     * `AttributeProviderFailed`, wrapping its failure: no decision is made,
     * recorded or reported, so nothing of the provider's message or values
     * reaches a decision, an event or the trace, and the provider is asked once
     * for the check.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException
     */
    public function testAFailingAttributeProviderAbortsTheCheck(): void
    {
        $user     = StubIdentity::create(['id' => 'reader-1']);
        $post     = StubIdentity::create(['id' => 'post-4']);
        $provider = new FailingResourceAttributes;

        $this->app?->instance(FailingResourceAttributes::class, $provider);

        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app?->make(ConfigRepository::class);
        $config->set('authorization.attributes.resources', [$post->getMorphClass() => FailingResourceAttributes::class]);

        $policy = EvaluationPolicy::fromArray(['name' => 'failing', 'statements' => [
            ['effect' => 'deny', 'actions' => ['posts:read'], 'conditions' => ['eq_if_exists' => ['resource.status' => 'archived']]],
            ['effect' => 'allow', 'actions' => ['posts:read'], 'conditions' => ['null' => ['resource.status' => true]]],
        ]]);

        Event::fake();

        $scope = Authorization::for($user)->withPolicies([$policy]);

        try {
            $scope->check('posts:read', $post);

            self::fail('The check is aborted.');
        } catch (AttributeProviderFailed $exception) {
            self::assertSame(FailingResourceAttributes::class, $exception->getProvider());
            self::assertSame('resource', $exception->getNamespace());
            self::assertStringNotContainsString(FailingResourceAttributes::MESSAGE, $exception->getMessage());
            self::assertSame(FailingResourceAttributes::MESSAGE, $exception->getPrevious()?->getMessage());
        }

        self::assertSame(1, $provider->calls);
        self::assertNull($scope->lastDecision());
        Event::assertNotDispatched(DecisionEvaluated::class);
        Event::assertNotDispatched(AuthorizationFailed::class);

        $this->expectException(AttributeProviderFailed::class);

        $scope->authorize('posts:read', $post);
    }

    /**
     * `authorize()` raises an insufficient authentication exception for an
     * allow whose requirement alone is unmet, carrying the reason and the
     * candidate requirement and nothing of the policy, after recording the
     * decision and firing `AuthorizationFailed`.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public function testAuthorizeRaisesInsufficientAuthentication(): void
    {
        Event::fake([AuthorizationFailed::class]);

        $user    = StubIdentity::create(['id' => '0d6a7f1e-5c2b-4e9a-8f3d-1b2c3d4e5f60']);
        $checker = new StubRequirementChecker(RequirementResult::unmet(['multifactor']));
        $manager = $this->inSession($user, 'session-1', $checker)->withPolicies([self::requiringPolicy()]);

        try {
            $manager->authorize('reports:export');
            self::fail('The check was allowed.');
        } catch (InsufficientAuthenticationException $exception) {
            self::assertSame(DecisionReason::INSUFFICIENT_AUTHENTICATION, $exception->getReason());
            self::assertSame(403, $exception->getCode());
            self::assertSame('This action requires further authentication.', $exception->getMessage());
            self::assertEquals([new UnmetRequirement(self::requirement(), ['multifactor'])], $exception->requirements());
            self::assertStringNotContainsString('step-up', \serialize($exception->requirements()));
            self::assertStringNotContainsString('Export', \serialize($exception->requirements()));
        }

        self::assertSame(DecisionReason::INSUFFICIENT_AUTHENTICATION, $manager->lastDecision()?->reason);
        self::assertEquals([new StatementReference('step-up', 0, null, 'Export')], $manager->lastDecision()->statements);
        Event::assertDispatched(
            AuthorizationFailed::class,
            static fn (AuthorizationFailed $event): bool => $event->decision->reason === DecisionReason::INSUFFICIENT_AUTHENTICATION,
        );
    }

    /**
     * A met requirement allows, and `authorize()` passes; a permission the
     * subject holds allows over an unmet one.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException
     */
    public function testAMetRequirementOrAHeldPermissionAllows(): void
    {
        Permission::create(['name' => 'reports:export', 'guard' => 'web']);

        $user = StubIdentity::create(['id' => '1e7b8a2f-6d3c-4fab-9e4d-2c3d4e5f6a71']);

        $met   = new StubRequirementChecker(RequirementResult::met());
        $unmet = new StubRequirementChecker(RequirementResult::unmet(['multifactor']));

        $this->inSession($user, 'session-1', $met)->withPolicies([self::requiringPolicy()])->authorize('reports:export');

        $user->givePermission('reports:export');

        $decision = $this->inSession($user, 'session-1', $unmet)->withPolicies([self::requiringPolicy()])->check('reports:export');

        self::assertTrue($decision->isAllowed());
        self::assertSame([], $decision->requirements);
        self::assertSame(TraceOutcome::HELD, $decision->trace[1]->outcome);
    }

    /**
     * A deny that applies wins over an unmet requirement, and `authorize()`
     * raises the plain denial.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException
     */
    public function testADenyWinsOverInsufficientAuthentication(): void
    {
        $user = StubIdentity::create(['id' => '2f8c9b3a-7e4d-4abc-8f5e-3d4e5f6a7b82']);
        $deny = EvaluationPolicy::fromArray(['name' => 'block', 'statements' => [['effect' => 'deny', 'actions' => ['reports:export']]]]);

        $this->expectException(AuthorizationException::class);

        $checker = new StubRequirementChecker(RequirementResult::unmet(['multifactor']));

        $this->inSession($user, 'session-1', $checker)->withPolicies([self::requiringPolicy(), $deny])->authorize('reports:export');
    }

    /**
     * A subject the caller names has no session, so its requirement is unmet
     * and the checker is never asked.
     *
     * @return void
     */
    public function testACallerNamedSubjectMeetsNoRequirement(): void
    {
        $checker = new StubRequirementChecker(RequirementResult::met());
        $user    = StubIdentity::create(['id' => '3a9d0c4b-8f5e-4bcd-9a6f-4e5f6a7b8c93']);

        $decision = $this->inSession($user, 'session-1', $checker)->for($user)->withPolicies([self::requiringPolicy()])->check('reports:export');

        self::assertSame(DecisionReason::INSUFFICIENT_AUTHENTICATION, $decision->reason);
        self::assertSame([], $checker->calls);
    }

    /**
     * The default checker meets nothing, so an allow stating a requirement
     * denies as insufficient authentication, every part unmet.
     *
     * @return void
     */
    public function testTheDefaultCheckerMeetsNothing(): void
    {
        $user = StubIdentity::create(['id' => '4b0e1d5c-9a6f-4cde-8b7a-5f6a7b8c9da4']);

        $decision = $this->inSession($user, 'session-1')->withPolicies([self::requiringPolicy()])->check('reports:export');

        self::assertSame(DecisionReason::INSUFFICIENT_AUTHENTICATION, $decision->reason);
        self::assertEquals([new UnmetRequirement(self::requirement(), ['multifactor', 'phishing_resistant'])], $decision->requirements);
    }

    /**
     * A checker that throws makes the requirement undecidable: the check is a
     * failed condition, never insufficient authentication.
     *
     * @return void
     */
    public function testACheckerThatThrowsIsAFailedCondition(): void
    {
        $user = StubIdentity::create(['id' => '5c1f2e6d-0b7a-4def-9c8b-6a7b8c9d0eb5']);

        $checker  = new StubRequirementChecker(new \RuntimeException('down'));
        $decision = $this->inSession($user, 'session-1', $checker)->withPolicies([self::requiringPolicy()])->check('reports:export');

        self::assertSame(DecisionReason::CONDITION_FAILED, $decision->reason);
        self::assertSame([], $decision->requirements);
    }

    /**
     * A decision that read a met requirement is the last decision only until
     * the requirement stops being met, and only in its own session.
     *
     * @return void
     */
    public function testTheLastDecisionIsFreshOnlyInItsSessionAndBeforeItsMetUntil(): void
    {
        Carbon::setTestNow('2026-11-06 12:00:00');

        $until   = new \DateTimeImmutable('2026-11-06 12:15:00');
        $user    = StubIdentity::create(['id' => '6d2a3f7e-1c8b-4ef0-8d9c-7b8c9d0e1fc6']);
        $manager = $this->inSession($user, 'session-1', new StubRequirementChecker(RequirementResult::met($until)));

        $decision = $manager->withPolicies([self::requiringPolicy()])->check('reports:export');

        self::assertTrue($decision->isAllowed());
        self::assertEquals(new RequirementFreshness('session-1', $until), $decision->freshness);
        self::assertSame($decision, $manager->lastDecision());

        Carbon::setTestNow('2026-11-06 12:15:00');

        self::assertNull($manager->lastDecision());

        Carbon::setTestNow('2026-11-06 12:00:00');

        self::assertSame($decision, $manager->lastDecision());
        self::assertNull($this->inSession($user, 'session-2')->lastDecision());

        Carbon::setTestNow();
    }

    /**
     * A decision that read no requirement is the last decision whatever the
     * session.
     *
     * @return void
     */
    public function testALastDecisionWithoutARequirementIsAlwaysFresh(): void
    {
        $user     = StubIdentity::create(['id' => '7e3b4a8f-2d9c-4f01-9eab-8c9d0e1f2ad7']);
        $policy   = EvaluationPolicy::fromArray(['name' => 'p', 'statements' => [['effect' => 'allow', 'actions' => ['reports:export']]]]);
        $decision = $this->inSession($user, 'session-1')->withPolicies([$policy])->check('reports:export');

        self::assertNull($decision->freshness);
        self::assertSame($decision, $this->inSession($user, 'session-2')->lastDecision());
    }

    /**
     * A decision that read a requirement with no subject resolved, as in a
     * console command or a guest request, is made outside a session, and is the
     * last decision there.
     *
     * @return void
     */
    public function testALastDecisionMadeWithNoSubjectResolvedIsReturned(): void
    {
        $user = StubIdentity::create(['id' => '8f4c5b9a-3eab-4012-8fbc-9d0e1f2a3be8']);

        /** @var \SineMacula\Laravel\Authorization\AuthorizationManager $manager */
        $manager = $this->app?->make(AuthorizationManager::class);

        self::assertNull($manager->currentSubject());

        $decision = $manager->for($user)->withPolicies([self::requiringPolicy()])->check('reports:export');

        self::assertEquals(new RequirementFreshness(null), $decision->freshness);
        self::assertSame($decision, $manager->lastDecision());
    }

    /**
     * A decision about a subject named with `for()`, which has no session, is
     * the last decision in the session of the request that recorded it, and in
     * no other.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public function testALastDecisionAboutANamedSubjectIsReturnedInTheRequestsSession(): void
    {
        $user  = StubIdentity::create(['id' => '9a5d6c0b-4fbc-4123-9acd-0e1f2a3b4cf9']);
        $other = StubIdentity::create(['id' => '0b6e7d1c-5acd-4234-8bde-1f2a3b4c5d0a']);

        try {
            $this->inSession($user, 'session-1')->for($other)->withPolicies([self::requiringPolicy()])->authorize('reports:export');
            self::fail('The check was allowed.');
        } catch (InsufficientAuthenticationException $exception) {
            self::assertSame(DecisionReason::INSUFFICIENT_AUTHENTICATION, $exception->getReason());
        }

        $decision = Authorization::lastDecision();

        self::assertNotNull($decision);
        self::assertSame(DecisionReason::INSUFFICIENT_AUTHENTICATION, $decision->reason);
        self::assertEquals(new RequirementFreshness(null), $decision->freshness);
        self::assertNull($this->inSession($user, 'session-2')->lastDecision());
    }

    /**
     * Assert that exactly one decision event was dispatched, for the check of
     * `posts:create` without a resource, carrying the supplied principal,
     * context and decision, and that no failure event was dispatched.
     *
     * @param  object  $principal
     * @param  array<string, mixed>  $context
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Decision  $decision
     * @return void
     */
    private static function assertSoleDecisionEvent(object $principal, array $context, Decision $decision): void
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
        self::assertSame($decision, $events[0]->decision);
        Event::assertNotDispatched(AuthorizationFailed::class);
    }

    /**
     * Return a policy allowing `reports:export` once multifactor and a
     * phishing-resistant authenticator are proved.
     *
     * @return \SineMacula\Laravel\Authorization\Evaluation\Policy
     */
    private static function requiringPolicy(): EvaluationPolicy
    {
        return EvaluationPolicy::fromArray(['name' => 'step-up', 'statements' => [[
            'sid'        => 'Export',
            'effect'     => 'allow',
            'actions'    => ['reports:export'],
            'conditions' => ['authentication_requirement' => ['authentication' => ['multifactor' => ['max_age' => 900], 'phishing_resistant' => []]]],
        ]]]);
    }

    /**
     * Return the requirement the policy states.
     *
     * @return \SineMacula\Laravel\Authorization\Evaluation\AuthenticationRequirement
     */
    private static function requirement(): AuthenticationRequirement
    {
        return new AuthenticationRequirement(['multifactor' => 900, 'phishing_resistant' => null]);
    }

    /**
     * Resolve the user as the subject in the session, with the checker bound
     * when one is given, and return a manager built afresh.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $user
     * @param  string|null  $session
     * @param  \SineMacula\Laravel\Authorization\Contracts\AuthenticationRequirementChecker|null  $checker
     * @return \SineMacula\Laravel\Authorization\AuthorizationManager
     */
    private function inSession(StubIdentity $user, ?string $session, ?AuthenticationRequirementChecker $checker = null): AuthorizationManager
    {
        $this->app?->instance(SubjectResolver::class, new FixedSubjectResolver(new Subject($user, $user, session: $session)));

        if ($checker !== null) {
            $this->app?->instance(AuthenticationRequirementChecker::class, $checker);
        }

        foreach (['authorization', AuthorizationManager::class, CheckContextFactory::class] as $abstract) {
            $this->app?->forgetInstance($abstract);
        }

        /** @var \SineMacula\Laravel\Authorization\AuthorizationManager */
        return $this->app?->make(AuthorizationManager::class);
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
