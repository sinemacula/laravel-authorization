<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Gate;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Concerns\HasPermissions;
use SineMacula\Laravel\Authorization\Concerns\HasPolicies;
use SineMacula\Laravel\Authorization\Concerns\HasRoles;
use SineMacula\Laravel\Authorization\Context\CheckContextFactory;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationRequirementChecker;
use SineMacula\Laravel\Authorization\Contracts\ResourceTenantResolver;
use SineMacula\Laravel\Authorization\Contracts\SessionPolicySource;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Evaluation\AuthenticationRequirement;
use SineMacula\Laravel\Authorization\Evaluation\CheckInput;
use SineMacula\Laravel\Authorization\Evaluation\Decision;
use SineMacula\Laravel\Authorization\Evaluation\DecisionProvenance;
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
use SineMacula\Laravel\Authorization\Exceptions\DependencyChangedException;
use SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;
use SineMacula\Laravel\Authorization\Exceptions\QueryScopeRefusedException;
use SineMacula\Laravel\Authorization\Exceptions\UnknownPermissionException;
use SineMacula\Laravel\Authorization\Exceptions\UnknownRoleException;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Services\BoundaryService;
use SineMacula\Laravel\Authorization\Services\GuardrailService;
use SineMacula\Laravel\Authorization\Services\ResourcePolicyService;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\AuthorizationScope;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\OperationScope;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResolvedTenant;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use SineMacula\Laravel\Authorization\Support\SessionScopes;
use Tests\Concerns\ReadsDispatchedEvents;
use Tests\Concerns\RefusesThePackage;
use Tests\Feature\Stubs\AuthenticatableIdentity;
use Tests\Feature\Stubs\Enums\IntBackedPermissionEnum;
use Tests\Feature\Stubs\Enums\PermissionEnum;
use Tests\Feature\Stubs\FailingResourceAttributes;
use Tests\Feature\Stubs\FixedResourceTenantResolver;
use Tests\Feature\Stubs\FixedSubjectResolver;
use Tests\Feature\Stubs\NarrowContractsGrantee;
use Tests\Feature\Stubs\PlanContextSource;
use Tests\Feature\Stubs\RecordingResourceAttributes;
use Tests\Feature\Stubs\RecordingSubjectAttributes;
use Tests\Feature\Stubs\ReservedContextSource;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubMachine;
use Tests\Feature\Stubs\StubRequirementChecker;
use Tests\Feature\Stubs\StubSecondIdentity;
use Tests\Feature\Stubs\StubSessionPolicySource;
use Tests\Feature\Stubs\StubSubjectResolver;
use Tests\Feature\Stubs\StubTenant;
use Tests\Feature\Stubs\StubTenantTree;
use Tests\Feature\Stubs\SuspendableIdentity;
use Tests\Fixtures\QueryScoping\ScopedPost;
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
    use ReadsDispatchedEvents, RefusesThePackage;

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

        (new AuthorizationServiceProvider($this->container()))->register();

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
     * A tree change reported while a delegated administration call runs marks
     * it moved, so it is tried again rather than written on the chains its
     * decisions read; a trusted one is never marked.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATreeChangeMarksADelegatedCallRunningMeanwhile(): void
    {
        $operation = new Operation('op', new Reference('user', 'admin'), CarbonImmutable::now('UTC'), false);
        $tenant    = new Reference('stub_tenant', 'account');

        $moved = OperationScope::run($operation, static function () use ($tenant): bool {
            $pins = OperationScope::pins();

            $pins?->validate();

            Authorization::treeChanged($tenant);

            try {
                $pins?->validate();
            } catch (DependencyChangedException) {
                return true;
            }

            return false;
        });

        self::assertTrue($moved);

        OperationScope::run(Operation::begin(), static function () use ($tenant): void {
            Authorization::treeChanged($tenant);

            self::assertNull(OperationScope::pins());
        });
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
        $this->container()->make(ConfigRepository::class)->set('app.debug', false);

        /** @var \Illuminate\Routing\Router $router */
        $router = $this->container()->make('router');
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
        self::assertEquals([...self::uncapped(), new TraceEntry(DecisionStage::ALLOW, TraceOutcome::HELD, null, [], null, 'posts:create')], $decision->trace);
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
        $config = $this->container()->make('config');
        $config->set('authorization.permission_enums', [PermissionEnum::class]);

        (new AuthorizationServiceProvider($this->container()))->boot();

        Permission::create(['id' => '70be15aa-1ce5-4c1f-87a5-1c8e91a02587', 'name' => 'posts:create', 'guard' => 'web']);

        $user = StubIdentity::create(['id' => 'd004aa1d-ff0c-4776-8a4c-d975b6c671a1']);
        $user->givePermission('posts:create');

        self::assertTrue(Authorization::for($user)->can('posts:create'));
        self::assertTrue(Gate::forUser($user)->allows('posts:create'));
    }

    /**
     * `permissionsFor()` lists each case's value, the permission name, of those
     * the subject is allowed, in the catalogue's order.
     *
     * @return void
     */
    public function testPermissionsForListsTheCaseValuesAllowed(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->container()->make('config');
        $config->set('authorization.permission_enums', [PermissionEnum::class]);

        Permission::create(['id' => '0d4a3f0e-2f5e-4c39-9b0b-4f8ab2a1c5d1', 'name' => PermissionEnum::POSTS_CREATE->value, 'guard' => 'web']);

        $user = StubIdentity::create(['id' => '7c3e9f12-55a4-4b8e-b0a7-2d1c6e8f9a03']);
        $user->givePermission(PermissionEnum::POSTS_CREATE->value);

        self::assertSame([PermissionEnum::POSTS_CREATE->value], Authorization::permissionsFor($user, AuthorizationScope::current()));
    }

    /**
     * The permission catalogue reads the configured enums when it is read,
     * after the boot validation, so `permissionsFor()` refuses an enum not
     * backed by strings, naming the entry, rather than skip it or fail with a
     * TypeError mid-request.
     *
     * @return void
     */
    public function testPermissionsForRefusesAnEnumNotBackedByStrings(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->container()->make('config');
        $config->set('authorization.permission_enums', [IntBackedPermissionEnum::class, PermissionEnum::class]);

        $user = StubIdentity::create(['id' => '5b0f6c1e-8d2a-4f3b-9e7c-1a4d2c6b8e90']);

        $user->givePermission(Permission::create(['name' => PermissionEnum::POSTS_DELETE->value]));

        $this->expectException(InvalidAuthorizationConfigException::class);
        $this->expectExceptionMessage('Invalid authorization config at \'authorization.permission_enums.0\'');

        Authorization::permissionsFor($user, AuthorizationScope::current());
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
            $this->container()->make(AuthorizationManager::class)->authorize('nope');
        } catch (AuthorizationException) {
            // Expected.
        }

        Event::assertDispatched(DecisionEvaluated::class);
        Event::assertDispatched(AuthorizationFailed::class);
    }

    /**
     * A refusal whose decision a listener replaced as the last decision, by
     * deciding another check, is reported once, naming the subject and no
     * previewer, since the manager is no preview.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InsufficientAuthenticationException
     */
    public function testARefusalWhoseDecisionWasReplacedNamesNoPreviewer(): void
    {
        $user = StubIdentity::create(['id' => 'u1']);

        $this->app?->instance(SubjectResolver::class, new FixedSubjectResolver(new Subject($user, $user)));
        $this->app?->forgetInstance(AuthorizationManager::class);

        /** @var \SineMacula\Laravel\Authorization\AuthorizationManager $manager */
        $manager = $this->app?->make(AuthorizationManager::class);

        /** @var \ArrayObject<int, \SineMacula\Laravel\Authorization\Events\AuthorizationFailed> $failed */
        $failed = new \ArrayObject;

        Event::listen(DecisionEvaluated::class, static function (DecisionEvaluated $event) use ($manager): void {
            if ($event->action !== 'posts:delete') {
                return;
            }

            $manager->check('posts:read');
        });
        Event::listen(AuthorizationFailed::class, static fn (AuthorizationFailed $event) => $failed->append($event));

        try {
            $manager->authorize('posts:delete');
            self::fail('The check was allowed.');
        } catch (AuthorizationException $exception) {
            self::assertSame(DecisionReason::NO_MATCH, $exception->getReason());
        }

        $reported = \array_values($failed->getArrayCopy());

        self::assertCount(1, $reported);
        self::assertSame('posts:delete', $reported[0]->action);
        self::assertEquals(Reference::of($user), $reported[0]->subject);
        self::assertNull($reported[0]->previewer);
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
            ...self::uncapped(),
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
            ...self::uncapped(),
            new TraceEntry(DecisionStage::ALLOW, TraceOutcome::NOT_APPLICABLE, new StatementReference('unrelated', 0)),
            new TraceEntry(DecisionStage::ALLOW, TraceOutcome::HELD, null, [], null, 'posts:create'),
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
            ...self::uncapped(),
            new TraceEntry(DecisionStage::ALLOW, TraceOutcome::UNDECIDABLE, new StatementReference('conditional-allow', 0), ['input.tenant' => false]),
            new TraceEntry(DecisionStage::ALLOW, TraceOutcome::HELD, null, [], null, 'posts:create'),
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

        self::assertSoleDecisionEvent($user, $decision);
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

        self::assertSoleDecisionEvent($user, $decision);
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

        $resources = \array_map(static fn (DecisionEvaluated $event): ?string => $event->resource, self::dispatchedEvents(DecisionEvaluated::class));

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
     * A decision the pipeline did not make is recorded and reported for the
     * current subject as a refusal of `authorize()` is: the last decision, its
     * decision event and its failure event, each naming the resource, and the
     * `AuthorizationException` carrying it is returned.
     *
     * @return void
     */
    public function testARefusalMadeElsewhereIsReportedAsAuthorizeReportsOne(): void
    {
        $user     = StubIdentity::create(['id' => '2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e']);
        $decision = Decision::deny(DecisionReason::ADMINISTRATION_CONFLICT, DecisionStage::ADMINISTRATION);

        Event::fake();

        $refusal = Authorization::for($user)->reportRefusal('posts:delete', ['posts', 7], $decision);

        self::assertSame($decision, $refusal->getDecision());
        self::assertSame(DecisionReason::ADMINISTRATION_CONFLICT, $refusal->getReason());
        self::assertSame($decision, Authorization::lastDecision());
        $evaluated = static fn (DecisionEvaluated $event): bool => [$event->resource, $event->subject?->id, $event->reason] === ['posts:7', $user->getKey(), $decision->reason];
        $failed    = static fn (AuthorizationFailed $event): bool => [$event->resource, $event->subject?->id, $event->action] === ['posts:7', $user->getKey(), 'posts:delete'];

        Event::assertDispatched(DecisionEvaluated::class, $evaluated);
        Event::assertDispatched(AuthorizationFailed::class, $failed);
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

        $failed = \array_map(static fn (AuthorizationFailed $event): ?string => $event->resource, self::dispatchedEvents(AuthorizationFailed::class));

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
        self::assertStringContainsString('allow', $manager->explain('posts:create', null, $caller)->toText());
        self::assertSame(['posts:create'], $manager->permissionsFor($user, AuthorizationScope::current(), $caller));
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
        self::assertSame(['resource.status' => true, 'resource.owner.id' => true, 'subject.department' => true], $decision->trace[3]->conditions);
        self::assertStringNotContainsString('draft', $decision->explain()->toText());
        self::assertStringNotContainsString('sales', $decision->explain()->toText());
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
            self::assertSame(DecisionReason::INSUFFICIENT_AUTHENTICATION, $exception->getDecision()?->reason);
            self::assertSame(403, $exception->getCode());
            self::assertSame('This action is unauthorized.', $exception->getMessage());
            self::assertEquals([new UnmetRequirement(self::requirement(), ['multifactor'])], $exception->requirements());
            self::assertStringNotContainsString('step-up', \serialize($exception->requirements()));
            self::assertStringNotContainsString('Export', \serialize($exception->requirements()));
        }

        self::assertSame(DecisionReason::INSUFFICIENT_AUTHENTICATION, $manager->lastDecision()?->reason);
        self::assertEquals([new StatementReference('step-up', 0, null, 'Export')], $manager->lastDecision()->statements);
        Event::assertDispatched(
            AuthorizationFailed::class,
            static fn (AuthorizationFailed $event): bool => $event->reason === DecisionReason::INSUFFICIENT_AUTHENTICATION,
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
        self::assertSame(TraceOutcome::HELD, $decision->trace[4]->outcome);
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
     * The last decision is kept with its provenance: the request's subject for
     * `check()`, the subject named with `for()` or translated with `forUser()`,
     * and nobody for a guest, never filled from the request's subject, each in
     * the request's tenant and application; listing actions leaves it as it
     * was, and forgetting the decision forgets it.
     *
     * @return void
     */
    public function testTheLastDecisionIsKeptWithWhoItWasAbout(): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $other  = StubIdentity::create(['id' => 'user-2']);
        $second = StubSecondIdentity::create(['id' => 'user-3']);
        $tenant = StubTenant::query()->create(['id' => 'tenant-1', 'name' => 'tenant-1']);
        $where  = new Reference($tenant->getMorphClass(), 'tenant-1');

        $this->app?->instance(SubjectResolver::class, new StubSubjectResolver($user, $tenant, 'admin'));
        $this->app?->forgetInstance(AuthorizationManager::class);
        $this->app?->forgetInstance('authorization');

        /** @var \SineMacula\Laravel\Authorization\AuthorizationManager $manager */
        $manager = $this->app?->make(AuthorizationManager::class);

        self::assertNull(Authorization::lastDecisionProvenance());

        $manager->check('posts:read');

        self::assertEquals(new DecisionProvenance(Reference::of($user), Reference::of($user), null, $where, 'admin'), $manager->lastDecisionProvenance());

        $manager->for($other)->check('posts:read');

        self::assertEquals(new DecisionProvenance(Reference::of($other), Reference::of($other), null, $where, 'admin'), Authorization::lastDecisionProvenance());

        $manager->forUser($second)->checkMany([new CheckInput('posts:read'), new CheckInput('posts:edit')]);

        self::assertEquals(new DecisionProvenance(Reference::of($second), Reference::of($second), null, $where, 'admin'), $manager->lastDecisionProvenance());

        $manager->forUser(null)->check('posts:read');

        $guest = $manager->lastDecisionProvenance();

        self::assertEquals(new DecisionProvenance(null, null, null, $where, 'admin'), $guest);
        self::assertFalse($guest?->isPreview());

        $manager->permissionsFor($user, AuthorizationScope::platform('web'));

        self::assertSame($guest, $manager->lastDecisionProvenance());

        $manager->forgetLastDecision();

        self::assertNull($manager->lastDecisionProvenance());
    }

    /**
     * The provenance goes with the decision: none once the decision has stopped
     * being fresh, or in another session, and the decision's again while it is
     * fresh.
     *
     * @return void
     */
    public function testTheLastDecisionsProvenanceGoesWithTheDecision(): void
    {
        Carbon::setTestNow('2026-11-06 12:00:00');

        $user    = StubIdentity::create(['id' => '1c7f8e2d-6bde-4345-9cef-2a3b4c5d6e1b']);
        $manager = $this->inSession($user, 'session-1', new StubRequirementChecker(RequirementResult::met(new \DateTimeImmutable('2026-11-06 12:15:00'))));

        $manager->withPolicies([self::requiringPolicy()])->check('reports:export');

        self::assertEquals(Reference::of($user), $manager->lastDecisionProvenance()?->subject);
        self::assertNull($this->inSession($user, 'session-2')->lastDecisionProvenance());

        Carbon::setTestNow('2026-11-06 12:15:00');

        self::assertNull($manager->lastDecisionProvenance());

        Carbon::setTestNow();
    }

    /**
     * A policy attached to a record allows the subject its principals name, by
     * reference, without the subject holding any permission, and nobody else;
     * the trace records each statement with the resource its policy is attached
     * to, and the explanation shows it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAResourcePolicyAllowsTheSubjectItNames(): void
    {
        $named = StubIdentity::create(['id' => 'user-1']);
        $other = StubIdentity::create(['id' => 'user-2']);
        $post  = ResourceReference::record('posts', '7');

        $share = ['sid' => 'share', 'effect' => 'allow', 'actions' => ['posts:read'], 'principals' => [$named->getMorphClass() . ':user-1']];

        self::attachToResource(self::resourcePolicy('sharing', [$share]), ['posts', 7]);

        $allowed = Authorization::for($named)->check('posts:read', $post);
        $denied  = Authorization::for($other)->check('posts:read', $post);

        self::assertTrue($allowed->isAllowed());
        self::assertSame(DecisionStage::ALLOW, $allowed->stage);
        self::assertSame('posts:7', $allowed->statements[0]->resource);
        self::assertStringContainsString('sharing[', $allowed->explain()->toText());
        self::assertStringContainsString('#0 sid="share" on "posts:7"', $allowed->explain()->toText());
        self::assertSame(DecisionReason::NO_MATCH, $denied->reason);
        self::assertSame(TraceOutcome::PRINCIPAL_MISMATCH, $denied->trace[3]->outcome);
        self::assertSame('posts:7', $denied->trace[3]->statement?->resource);
        self::assertSame(TraceOutcome::NOT_HELD, $denied->trace[4]->outcome);
        self::assertFalse(Authorization::for($named)->can('posts:read', ResourceReference::record('posts', '8')));
    }

    /**
     * A policy attached to a type applies to a check on any record of the type
     * and on the type alone; a check on an opaque identifier, or on no
     * resource, reads no resource policy.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATypesResourcePolicyAppliesToItsRecordsAndToTheTypeAlone(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);

        self::attachToResource(self::resourcePolicy('creators', [['effect' => 'allow', 'actions' => ['posts:*'], 'principals' => [$user->getMorphClass() . ':user-1']]]), 'posts');

        self::assertTrue(Authorization::for($user)->can('posts:create', ResourceReference::type('posts')));
        self::assertTrue(Authorization::for($user)->can('posts:read', ['posts', 9]));
        self::assertFalse(Authorization::for($user)->can('posts:read', 'posts:9'));
        self::assertFalse(Authorization::for($user)->can('posts:read'));
        self::assertFalse(Authorization::for($user)->can('posts:read', ResourceReference::type('docs')));
    }

    /**
     * A resource policy's deny applies to everyone checking the resource,
     * whatever they hold: a subject holding the permission and an identity
     * policy allowing the action is denied by it, and the decision names it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAResourcePolicysDenyAppliesToEveryone(): void
    {
        Permission::create(['name' => 'posts:delete']);

        $holder = StubIdentity::create(['id' => 'user-1']);
        $other  = StubIdentity::create(['id' => 'user-2']);

        $holder->givePermission('posts:delete');
        $holder->attachPolicy(Policy::create(['name' => 'mine', 'document' => ['statements' => [['effect' => 'allow', 'actions' => ['posts:delete']]]]]));

        self::assertTrue(Authorization::for($holder)->can('posts:delete', ['posts', 7]));

        self::attachToResource(self::resourcePolicy('locked', [['sid' => 'lock', 'effect' => 'deny', 'actions' => ['posts:delete']]]), ['posts', 7]);

        foreach ([$holder, $other] as $subject) {
            $decision = Authorization::for($subject)->check('posts:delete', ['posts', 7]);

            self::assertSame(DecisionReason::EXPLICIT_DENY, $decision->reason);
            self::assertSame(['lock'], \array_map(static fn (StatementReference $statement): ?string => $statement->sid, $decision->statements));
            self::assertSame('posts:7', $decision->statements[0]->resource);
        }

        self::assertTrue(Authorization::for($holder)->can('posts:delete', ['posts', 8]));
    }

    /**
     * A role selector names whoever holds the role, by its key, in the scope
     * the check is decided in: not a holder of the role in another tenant, or
     * for another application, nor a holder of another role of the same name.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARoleSelectorNamesTheHoldersOfTheRoleInTheScope(): void
    {
        [$tenantA, $tenantB] = \array_map(static fn (string $id): StubTenant => StubTenant::query()->create(['id' => $id, 'name' => $id]), ['tenant-a', 'tenant-b']);

        $editor    = Role::create(['name' => 'editor']);
        $lookalike = Role::create(['name' => 'editor', 'tenant_type' => $tenantA->getMorphClass(), 'tenant_id' => 'tenant-a']);
        $inA       = StubIdentity::create(['id' => 'in-a']);
        $inB       = StubIdentity::create(['id' => 'in-b']);
        $onMobile  = StubIdentity::create(['id' => 'on-mobile']);
        $similar   = StubIdentity::create(['id' => 'similar']);

        $inA->assignRole($editor, null, $tenantA);
        $inB->assignRole($editor, null, $tenantB);
        $onMobile->assignRole($editor, application: 'mobile');
        $similar->assignRole($lookalike, null, $tenantA);

        self::attachToResource(self::resourcePolicy('editors', [['effect' => 'allow', 'actions' => ['posts:edit'], 'principals' => ['role:' . $editor->id]]]), 'posts');

        $can = function (StubIdentity $user, ?StubTenant $tenant, ?string $application = null): bool {
            $this->app?->instance(SubjectResolver::class, new StubSubjectResolver($user, $tenant, $application));
            $this->app?->forgetInstance(ResolvedTenant::class);

            return Authorization::for($user)->can('posts:edit', ['posts', 7]);
        };

        self::assertTrue($can($inA, $tenantA));
        self::assertFalse($can($inB, $tenantA));
        self::assertTrue($can($inB, $tenantB));
        self::assertFalse($can($onMobile, null, 'admin'));
        self::assertTrue($can($onMobile, null, 'mobile'));
        self::assertFalse($can($similar, $tenantA));
    }

    /**
     * A role selector names the holders of the roles below the role too, as a
     * policy attached to the role reaches them, so the holder of a child role
     * is allowed by a resource policy naming its parent, and the holder of the
     * parent is not allowed by one naming the child.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARoleSelectorNamesTheHoldersOfTheRolesBelowIt(): void
    {
        $author  = Role::create(['name' => 'author']);
        $editor  = Role::create(['name' => 'editor', 'parent_id' => $author->id]);
        $writer  = StubIdentity::create(['id' => 'writer']);
        $checker = StubIdentity::create(['id' => 'checker']);

        $writer->assignRole($author);
        $checker->assignRole($editor);

        self::attachToResource(self::resourcePolicy('authors', [['effect' => 'allow', 'actions' => ['posts:edit'], 'principals' => ['role:' . $author->id]]]), 'posts');
        self::attachToResource(self::resourcePolicy('editors', [['effect' => 'allow', 'actions' => ['posts:delete'], 'principals' => ['role:' . $editor->id]]]), 'posts');

        self::assertTrue(Authorization::for($checker)->can('posts:edit', ['posts', 7]));
        self::assertTrue(Authorization::for($checker)->can('posts:delete', ['posts', 7]));
        self::assertTrue(Authorization::for($writer)->can('posts:edit', ['posts', 7]));
        self::assertFalse(Authorization::for($writer)->can('posts:delete', ['posts', 7]));
    }

    /**
     * A resource policy's allow never reaches across tenants: a resource of a
     * tenant outside the subject's scope is still denied as `tenant_scope`
     * before any policy is read, while one in scope is allowed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAResourcePolicyNeverAllowsAnOutOfScopeResource(): void
    {
        [$tenantA, $tenantB] = \array_map(static fn (string $id): StubTenant => StubTenant::query()->create(['id' => $id, 'name' => $id]), ['tenant-a', 'tenant-b']);

        $user  = StubIdentity::create(['id' => 'user-1']);
        $share = ['effect' => 'allow', 'actions' => ['posts:read'], 'principals' => [$user->getMorphClass() . ':user-1']];

        self::attachToResource(self::resourcePolicy('sharing', [$share]), 'posts');

        $this->resolvePrincipalAs($user);
        $this->app?->instance(SubjectResolver::class, new StubSubjectResolver($user, $tenantA));
        $this->app?->forgetInstance(ResolvedTenant::class);

        $outside = Authorization::check('posts:read', ResourceReference::record('posts', '7', Reference::of($tenantB)));

        self::assertSame(DecisionReason::TENANT_SCOPE, $outside->reason);
        self::assertSame([], $outside->trace);
        self::assertTrue(Authorization::can('posts:read', ResourceReference::record('posts', '7', Reference::of($tenantA))));
    }

    /**
     * A deny a tenant attaches to its own record applies to everyone checking
     * it, also to a subject the tenant stage admits at platform scope through a
     * platform-wide permission, from another tenant or from none; the tenant's
     * allows do not reach that subject there.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantsResourcePolicyDenyHoldsAcrossThePlatformFallback(): void
    {
        [$tenantA, $tenantB] = \array_map(static fn (string $id): StubTenant => StubTenant::query()->create(['id' => $id, 'name' => $id]), ['tenant-a', 'tenant-b']);

        Permission::create(['name' => 'posts:delete']);
        Permission::create(['name' => 'posts:read']);

        $support = StubIdentity::create(['id' => 'support']);

        $support->givePermission('posts:delete');
        $support->givePermission('posts:read');

        $lock = self::resourcePolicy('lock', [
            ['sid' => 'lock', 'effect' => 'deny', 'actions' => ['posts:delete']],
            ['sid' => 'share', 'effect' => 'allow', 'actions' => ['posts:read'], 'principals' => [$support->getMorphClass() . ':support']],
        ]);

        $service = ResourcePolicyService::instance();

        self::assertInstanceOf(ResourcePolicyService::class, $service);

        $service->attach($lock, ['posts', 7], $tenantB);

        $post = ResourceReference::record('posts', '7', Reference::of($tenantB));

        foreach ([$tenantA, null, $tenantB] as $tenant) {
            $this->app?->instance(SubjectResolver::class, new StubSubjectResolver($support, $tenant));
            $this->app?->forgetInstance(ResolvedTenant::class);

            $denied = Authorization::for($support)->check('posts:delete', $post);
            $read   = Authorization::for($support)->check('posts:read', $post);

            self::assertSame(DecisionReason::EXPLICIT_DENY, $denied->reason);
            self::assertSame(['lock'], \array_map(static fn (StatementReference $statement): ?string => $statement->sid, $denied->statements));
            self::assertTrue($read->isAllowed());
            self::assertSame($tenant === $tenantB ? ['share'] : [], \array_map(static fn (StatementReference $statement): ?string => $statement->sid, $read->statements));
        }
    }

    /**
     * A check that a resource policy's role selector decides reads the roles
     * once: the next check on the record runs no query of the roles or their
     * hierarchy.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARoleSelectorReadsTheRolesOnceAcrossChecks(): void
    {
        $author = Role::create(['name' => 'author']);
        $editor = Role::create(['name' => 'editor', 'parent_id' => $author->id]);
        $user   = StubIdentity::create(['id' => 'user-1']);

        $user->assignRole($editor);

        self::attachToResource(self::resourcePolicy('authors', [['effect' => 'allow', 'actions' => ['posts:edit'], 'principals' => ['role:' . $author->id]]]), 'posts');

        self::assertTrue(Authorization::for($user)->can('posts:edit', ['posts', 7]));

        DB::enableQueryLog();
        DB::flushQueryLog();

        self::assertTrue(Authorization::for($user)->can('posts:edit', ['posts', 7]));
        self::assertTrue(Authorization::for($user)->can('posts:edit', ['posts', 8]));

        $roles = \array_filter(DB::getQueryLog(), static fn (array $query): bool => \str_contains($query['query'], 'roles'));

        self::assertSame([], $roles);

        DB::disableQueryLog();
    }

    /**
     * An attachment or detachment takes effect on the next check in the
     * request, and a per-call override evaluates only the policies it names.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAResourceAttachmentTakesEffectOnTheNextCheck(): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $policy = self::resourcePolicy('sharing', [['effect' => 'allow', 'actions' => ['posts:read'], 'principals' => [$user->getMorphClass() . ':user-1']]]);

        self::assertFalse(Authorization::for($user)->can('posts:read', ['posts', 7]));

        self::attachToResource($policy, ['posts', 7]);

        self::assertTrue(Authorization::for($user)->can('posts:read', ['posts', 7]));
        self::assertFalse(Authorization::for($user)->withPolicies([])->can('posts:read', ['posts', 7]));

        DB::enableQueryLog();
        DB::flushQueryLog();

        self::assertTrue(Authorization::for($user)->can('posts:read', ['posts', 7]));
        $read = \array_filter(DB::getQueryLog(), static fn (array $query): bool => \str_contains($query['query'], 'resource_policies'));

        self::assertSame([], $read);

        DB::disableQueryLog();

        $service = ResourcePolicyService::instance();
        $service?->detach($policy, ['posts', 7]);

        self::assertFalse(Authorization::for($user)->can('posts:read', ['posts', 7]));
    }

    /**
     * A resource policy whose document cannot be read denies every check on the
     * resource as an invalid policy.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnUnreadableResourcePolicyDeniesEveryCheckOnTheResource(): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $policy = self::resourcePolicy('broken', [['effect' => 'deny', 'actions' => ['posts:delete']]]);

        $user->givePermission(Permission::create(['name' => 'posts:read']));
        self::attachToResource($policy, ['posts', 7]);

        DB::table('policies')->where('id', $policy->id)->update(['document' => '{"statements":[{"effect":"deny"}]}']);

        self::assertSame(DecisionReason::INVALID_POLICY, Authorization::for($user)->check('posts:read', ['posts', 7])->reason);
        self::assertTrue(Authorization::for($user)->can('posts:read', ['posts', 8]));
    }

    /**
     * A boundary caps every allow source: a permission held directly or through
     * a role, an identity policy's allow, a role policy's allow and a resource
     * policy's allow naming the subject are each denied as `boundary` at the
     * boundary stage when the boundary does not allow the action, and allowed
     * again once the boundary is removed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABoundaryCapsEveryAllowSource(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);
        $role = Role::create(['name' => 'editor']);
        $post = ResourceReference::record('posts', '7');

        $user->givePermission(Permission::create(['name' => 'posts:edit']));
        $role->givePermission(Permission::create(['name' => 'posts:review']));
        $role->attachPolicy(self::resourcePolicy('role-allow', [['effect' => 'allow', 'actions' => ['posts:archive']]]));
        $user->assignRole($role);
        $user->attachPolicy(self::resourcePolicy('own-allow', [['effect' => 'allow', 'actions' => ['posts:publish']]]));
        $sharing = ['effect' => 'allow', 'actions' => ['posts:delete'], 'principals' => [$user->getMorphClass() . ':user-1']];

        self::attachToResource(self::resourcePolicy('sharing', [$sharing]), ['posts', 7]);

        self::boundaries()->set($user, self::resourcePolicy('read-only', [['effect' => 'allow', 'actions' => ['posts:read']]]));

        foreach (['posts:edit', 'posts:review', 'posts:archive', 'posts:publish', 'posts:delete'] as $action) {
            $decision = Authorization::for($user)->check($action, $post);

            self::assertSame(DecisionReason::BOUNDARY, $decision->reason, $action);
            self::assertSame(DecisionStage::BOUNDARY, $decision->stage, $action);
            self::assertSame([], $decision->statements, $action);
            self::assertNotContains(DecisionStage::ALLOW, \array_map(static fn (TraceEntry $entry): DecisionStage => $entry->stage, $decision->trace), $action);
        }

        self::assertFalse(Authorization::for($user)->can('posts:read', $post));

        self::boundaries()->remove($user);

        foreach (['posts:edit', 'posts:review', 'posts:archive', 'posts:publish', 'posts:delete'] as $action) {
            self::assertTrue(Authorization::for($user)->can($action, $post), $action);
        }
    }

    /**
     * What a boundary allows is still decided by the allows: a boundary grants
     * nothing, so an action it allows that nothing else allows is denied at the
     * implicit stage, and one a permission allows is allowed, the trace running
     * through every stage in order.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABoundaryGrantsNothing(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);

        $user->givePermission(Permission::create(['name' => 'posts:edit']));
        self::boundaries()->set($user, self::resourcePolicy('editing', [['effect' => 'allow', 'actions' => ['posts:edit', 'posts:read']]]));

        $denied  = Authorization::for($user)->check('posts:read');
        $allowed = Authorization::for($user)->check('posts:edit');

        self::assertSame(DecisionReason::NO_MATCH, $denied->reason);
        self::assertSame(DecisionStage::IMPLICIT, $denied->stage);
        self::assertTrue($allowed->isAllowed());
        self::assertSame(
            [
                [DecisionStage::GUARDRAIL, TraceOutcome::UNCAPPED],
                [DecisionStage::BOUNDARY, TraceOutcome::MATCHED],
                [DecisionStage::SESSION, TraceOutcome::UNCAPPED],
                [DecisionStage::ALLOW, TraceOutcome::HELD],
            ],
            \array_map(static fn (TraceEntry $entry): array => [$entry->stage, $entry->outcome], $allowed->trace),
        );
        self::assertSame('editing', $allowed->trace[1]->statement?->policy);
    }

    /**
     * A deny wins over every allow source, a boundary that allows the action
     * included, and a boundary's own deny statement denies at the deny stage
     * whatever allows the action.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADenyBeatsEveryAllowSource(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);
        $role = Role::create(['name' => 'editor']);
        $post = ResourceReference::record('posts', '7');

        $user->givePermission(Permission::create(['name' => 'posts:edit']));
        $role->attachPolicy(self::resourcePolicy('role-allow', [['effect' => 'allow', 'actions' => ['posts:edit', 'posts:read']]]));
        $user->assignRole($role);
        $sharing = ['effect' => 'allow', 'actions' => ['posts:edit', 'posts:read'], 'principals' => [$user->getMorphClass() . ':user-1']];

        self::attachToResource(self::resourcePolicy('sharing', [$sharing]), ['posts', 7]);
        self::boundaries()->set($user, self::resourcePolicy('bounded', [
            ['effect' => 'allow', 'actions' => ['posts:edit', 'posts:read']],
            ['effect' => 'deny', 'actions' => ['posts:read']],
        ]));

        self::assertTrue(Authorization::for($user)->can('posts:edit', $post));

        $boundaryDeny = Authorization::for($user)->check('posts:read', $post);

        self::assertSame(DecisionReason::EXPLICIT_DENY, $boundaryDeny->reason);
        self::assertSame(DecisionStage::DENY, $boundaryDeny->stage);
        self::assertSame('bounded', $boundaryDeny->statements[0]->policy);

        $user->attachPolicy(self::resourcePolicy('no-editing', [['effect' => 'deny', 'actions' => ['posts:edit']]]));

        $denied = Authorization::for($user)->check('posts:edit', $post);

        self::assertSame(DecisionReason::EXPLICIT_DENY, $denied->reason);
        self::assertSame(DecisionStage::DENY, $denied->stage);
        self::assertSame(['no-editing'], \array_map(static fn (StatementReference $statement): string => $statement->policy, $denied->statements));
        self::assertSame(['deny'], \array_values(\array_unique(\array_map(static fn (TraceEntry $entry): string => $entry->stage->value, $denied->trace))));
    }

    /**
     * Every boundary that applies is intersected: a tenant's boundary never
     * replaces the platform's, so in the tenant only what both allow passes,
     * and outside it the platform's alone applies.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testThePlatformAndTenantBoundariesIntersect(): void
    {
        $tenant = StubTenant::query()->create(['id' => 'tenant-a', 'name' => 'tenant-a']);
        $user   = StubIdentity::create(['id' => 'user-1']);

        foreach (['posts:read', 'posts:edit', 'posts:publish'] as $action) {
            $user->givePermission(Permission::create(['name' => $action]));
        }

        self::boundaries()->set($user, self::resourcePolicy('platform-cap', [['effect' => 'allow', 'actions' => ['posts:read', 'posts:edit']]]));
        self::boundaries()->set($user, self::resourcePolicy('tenant-cap', [['effect' => 'allow', 'actions' => ['posts:read', 'posts:publish']]]), $tenant);

        $this->resolvePrincipalAs($user);

        self::assertTrue(Authorization::can('posts:read'));
        self::assertTrue(Authorization::can('posts:edit'));
        self::assertFalse(Authorization::can('posts:publish'));

        $this->app?->instance(SubjectResolver::class, new StubSubjectResolver($user, $tenant));
        $this->app?->forgetInstance(ResolvedTenant::class);

        self::assertTrue(Authorization::can('posts:read'));
        self::assertSame(DecisionReason::BOUNDARY, Authorization::check('posts:edit')->reason);
        self::assertSame(DecisionReason::BOUNDARY, Authorization::check('posts:publish')->reason);
    }

    /**
     * The boundaries of the subject's principal and of its identity are
     * intersected: only what both allow passes.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testThePrincipalAndIdentityBoundariesIntersect(): void
    {
        $principal = SuspendableIdentity::create(['id' => 'account-1']);
        $identity  = StubSecondIdentity::create(['id' => 'person-1']);

        foreach (['posts:read', 'posts:edit', 'posts:publish'] as $action) {
            $principal->givePermission(Permission::create(['name' => $action]));
        }

        self::boundaries()->set($principal, self::resourcePolicy('account-cap', [['effect' => 'allow', 'actions' => ['posts:read', 'posts:edit']]]));
        self::boundaries()->set($identity, self::resourcePolicy('person-cap', [['effect' => 'allow', 'actions' => ['posts:read', 'posts:publish']]]));

        $this->app?->instance(SubjectResolver::class, new FixedSubjectResolver(new Subject($principal, $identity)));

        $manager = $this->app?->make(AuthorizationManager::class);
        self::assertNotNull($manager);

        self::assertTrue($manager->can('posts:read'));
        self::assertSame(DecisionReason::BOUNDARY, $manager->check('posts:edit')->reason);
        self::assertSame(DecisionReason::BOUNDARY, $manager->check('posts:publish')->reason);
    }

    /**
     * A boundary caps a principal and an identity that hold their grants
     * through the narrow contracts alone, not as authorizable identities: a
     * permission either holds is denied as `boundary` when a boundary of either
     * does not allow it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABoundaryCapsAGranteeOfTheNarrowContracts(): void
    {
        $principal = NarrowContractsGrantee::query()->create(['id' => 'account-1']);
        $identity  = NarrowContractsGrantee::query()->create(['id' => 'person-1']);

        $principal->givePermission(Permission::create(['name' => 'posts:read']));
        $principal->givePermission(Permission::create(['name' => 'posts:delete']));
        $identity->givePermission(Permission::create(['name' => 'posts:edit']));

        $this->app?->instance(SubjectResolver::class, new FixedSubjectResolver(new Subject($principal, $identity)));

        $manager = $this->app?->make(AuthorizationManager::class);
        self::assertNotNull($manager);

        self::assertTrue($manager->can('posts:delete'));

        self::boundaries()->set($principal, self::resourcePolicy('account-cap', [['effect' => 'allow', 'actions' => ['posts:read', 'posts:edit']]]));

        self::assertTrue($manager->can('posts:read'));
        self::assertTrue($manager->can('posts:edit'));
        self::assertSame(DecisionReason::BOUNDARY, $manager->check('posts:delete')->reason);

        self::boundaries()->set($identity, self::resourcePolicy('person-cap', [['effect' => 'allow', 'actions' => ['posts:read']]]));

        self::assertTrue($manager->can('posts:read'));
        self::assertSame(DecisionReason::BOUNDARY, $manager->check('posts:edit')->reason);
        self::assertSame(DecisionStage::BOUNDARY, $manager->check('posts:edit')->stage);
    }

    /**
     * An allow whose authentication requirement alone is unmet is reported as
     * `insufficient_authentication` only once every boundary lets the action
     * through; a boundary that does not allow it denies as `boundary`, and an
     * override of the policies never lifts a boundary.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testInsufficientAuthenticationComesOnlyAfterTheBoundaries(): void
    {
        $user    = StubIdentity::create(['id' => 'user-1']);
        $checker = new StubRequirementChecker(RequirementResult::unmet(['multifactor']));
        $policy  = self::resourcePolicy('cap', [['effect' => 'allow', 'actions' => ['posts:read']]]);

        self::boundaries()->set($user, $policy);

        $capped = $this->inSession($user, 'session-1', $checker)->withPolicies([self::requiringPolicy()])->check('reports:export');

        self::assertSame(DecisionReason::BOUNDARY, $capped->reason);
        self::assertSame([], $capped->requirements);

        $policy->update(['document' => ['statements' => [['effect' => 'allow', 'actions' => ['posts:read', 'reports:export']]]]]);

        $stepUp = $this->inSession($user, 'session-1', $checker)->withPolicies([self::requiringPolicy()])->check('reports:export');

        self::assertSame(DecisionReason::INSUFFICIENT_AUTHENTICATION, $stepUp->reason);
        self::assertCount(1, $stepUp->requirements);
    }

    /**
     * With no boundary nothing is capped, and the boundary stage says so.
     *
     * @return void
     */
    public function testNoBoundaryMeansNoCap(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);

        $user->givePermission(Permission::create(['name' => 'posts:edit']));

        $decision = Authorization::for($user)->check('posts:edit');

        self::assertTrue($decision->isAllowed());
        self::assertEquals(new TraceEntry(DecisionStage::BOUNDARY, TraceOutcome::UNCAPPED), $decision->trace[1]);
        self::assertStringContainsString('[boundary] boundaries: uncapped', $decision->explain()->toText());
    }

    /**
     * A boundary whose document cannot be read denies every check for its
     * grantee as an invalid policy, rather than lifting the cap.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnUnreadableBoundaryDeniesAsAnInvalidPolicy(): void
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $policy = self::resourcePolicy('cap', [['effect' => 'allow', 'actions' => ['posts:edit']]]);

        $user->givePermission(Permission::create(['name' => 'posts:edit']));
        self::boundaries()->set($user, $policy);

        DB::table('policies')->where('id', $policy->getKey())->update(['document' => '{"statements": "broken"}']);

        $decision = Authorization::for($user)->check('posts:edit');

        self::assertSame(DecisionReason::INVALID_POLICY, $decision->reason);
        self::assertSame(DecisionStage::DENY, $decision->stage);
    }

    /**
     * Setting, replacing and removing a boundary, and rewriting its policy,
     * each take effect on the next check through a warm persistent cache.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testBoundaryChangesInvalidateTheCachedResolution(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app?->make(ConfigRepository::class);
        $config->set('authorization.cache.store', 'array');

        (new AuthorizationServiceProvider($this->container()))->register();

        $user  = StubIdentity::create(['id' => 'user-1']);
        $read  = self::resourcePolicy('read-cap', [['effect' => 'allow', 'actions' => ['posts:read']]]);
        $edit  = self::resourcePolicy('edit-cap', [['effect' => 'allow', 'actions' => ['posts:edit']]]);
        $check = static fn (): bool => Authorization::for($user)->can('posts:edit');

        $user->givePermission(Permission::create(['name' => 'posts:edit']));

        self::assertTrue($check());

        self::boundaries()->set($user, $read);

        self::assertFalse($check());

        self::boundaries()->set($user, $edit);

        self::assertTrue($check());

        $edit->update(['document' => ['statements' => [['effect' => 'allow', 'actions' => ['posts:read']]]]]);

        self::assertFalse($check());

        self::boundaries()->remove($user);

        self::assertTrue($check());
    }

    /**
     * Once warm, a check about a subject with boundaries reads nothing; cold,
     * the boundaries and their documents are read in one query for the grantee.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testBoundariesAreReadInOneQueryAndNoneOnceWarm(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);

        $user->givePermission(Permission::create(['name' => 'posts:edit']));
        self::boundaries()->set($user, self::resourcePolicy('cap', [['effect' => 'allow', 'actions' => ['posts:edit']]]));

        $this->resolvePrincipalAs($user);

        DB::enableQueryLog();
        DB::flushQueryLog();

        self::assertTrue(Authorization::can('posts:edit'));

        $cold = \array_filter(DB::getQueryLog(), static fn (array $query): bool => \str_contains($query['query'], 'authorizable_boundaries'));

        DB::flushQueryLog();

        self::assertTrue(Authorization::can('posts:edit'));
        self::assertFalse(Authorization::can('posts:read'));

        $warm = DB::getQueryLog();

        DB::disableQueryLog();

        self::assertCount(1, $cold);
        self::assertSame([], $warm);
    }

    /**
     * A guardrail caps every allow source: a permission held directly or
     * through a role, an identity policy's allow, a role policy's allow and a
     * resource policy's allow naming the subject are each denied as `guardrail`
     * at the guardrail stage, naming the guardrail, when it does not allow the
     * action, a policy override included; once the guardrail is removed each is
     * allowed again.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGuardrailCapsEveryAllowSource(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);
        $role = Role::create(['name' => 'editor']);
        $post = ResourceReference::record('posts', '7');

        $user->givePermission(Permission::create(['name' => 'posts:edit']));
        $role->givePermission(Permission::create(['name' => 'posts:review']));
        $role->attachPolicy(self::resourcePolicy('role-allow', [['effect' => 'allow', 'actions' => ['posts:archive']]]));
        $user->assignRole($role);
        $user->attachPolicy(self::resourcePolicy('own-allow', [['effect' => 'allow', 'actions' => ['posts:publish']]]));
        $sharing = ['effect' => 'allow', 'actions' => ['posts:delete'], 'principals' => [$user->getMorphClass() . ':user-1']];

        self::attachToResource(self::resourcePolicy('sharing', [$sharing]), ['posts', 7]);

        $rail  = self::resourcePolicy('read-only', [['effect' => 'allow', 'actions' => ['posts:read']]]);
        $actor = self::guardrailManager();

        self::guardrails()->set($rail, null, ActingContext::for($actor));

        foreach (['posts:edit', 'posts:review', 'posts:archive', 'posts:publish', 'posts:delete'] as $action) {
            $decision = Authorization::for($user)->check($action, $post);

            self::assertSame(DecisionReason::GUARDRAIL, $decision->reason, $action);
            self::assertSame(DecisionStage::GUARDRAIL, $decision->stage, $action);
            self::assertSame([], $decision->statements, $action);
            $refusal = new TraceEntry(DecisionStage::GUARDRAIL, TraceOutcome::REFUSED, null, [], "read-only[{$rail->id}]");

            self::assertEquals($refusal, $decision->trace[\count($decision->trace) - 1], $action);
            self::assertNotContains(DecisionStage::ALLOW, \array_map(static fn (TraceEntry $entry): DecisionStage => $entry->stage, $decision->trace), $action);
        }

        $everything = EvaluationPolicy::fromArray(['name' => 'all', 'statements' => [['effect' => 'allow', 'actions' => ['*']]]]);
        $override   = Authorization::for($user)->withPolicies([$everything])->check('posts:edit');

        self::assertSame(DecisionReason::GUARDRAIL, $override->reason);

        self::guardrails()->remove($rail, null, ActingContext::for($actor));

        foreach (['posts:edit', 'posts:review', 'posts:archive', 'posts:publish', 'posts:delete'] as $action) {
            self::assertTrue(Authorization::for($user)->can($action, $post), $action);
        }
    }

    /**
     * The platform's guardrails and those of the check's tenant and every one
     * of its ancestors are intersected, a tenant's reaching its whole subtree:
     * only what every one of them allows passes, and a sibling's tenant and the
     * platform are capped by their own chain alone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testThePlatformTenantAndAncestorGuardrailsIntersect(): void
    {
        $tenant                           = static fn (string $id): StubTenant => StubTenant::query()->create(['id' => $id, 'name' => $id]);
        [$org, $account, $team, $sibling] = \array_map($tenant, ['org', 'account', 'team', 'sibling']);

        $this->app?->instance(TenantTree::class, (new StubTenantTree)
            ->put(Reference::of($account), Reference::of($org))
            ->put(Reference::of($team), Reference::of($account))
            ->put(Reference::of($sibling), Reference::of($org)));

        $user    = StubIdentity::create(['id' => 'user-1']);
        $actor   = self::guardrailManager();
        $actions = ['posts:read', 'posts:edit', 'posts:publish', 'posts:delete'];

        foreach ($actions as $action) {
            $user->givePermission(Permission::create(['name' => $action]));
        }

        self::guardrails()->set(self::resourcePolicy('platform', [['effect' => 'allow', 'actions' => $actions]]), null, ActingContext::for($actor));
        self::guardrails()->set(self::resourcePolicy('org', [['effect' => 'allow', 'actions' => ['posts:read', 'posts:edit', 'posts:publish']]]), $org, ActingContext::for($actor));
        self::guardrails()->set(self::resourcePolicy('account', [['effect' => 'allow', 'actions' => ['posts:read', 'posts:edit']]]), $account, ActingContext::for($actor));

        $allowed = function (?StubTenant $tenant) use ($user, $actions): array {
            $this->resolveInTenant($user, $tenant);

            return \array_values(\array_filter($actions, static fn (string $action): bool => Authorization::can($action)));
        };

        self::assertSame(['posts:read', 'posts:edit'], $allowed($team));
        self::assertSame(['posts:read', 'posts:edit'], $allowed($account));
        self::assertSame(['posts:read', 'posts:edit', 'posts:publish'], $allowed($org));
        self::assertSame(['posts:read', 'posts:edit', 'posts:publish'], $allowed($sibling));
        self::assertSame($actions, $allowed(null));

        $this->resolveInTenant($user, $team);

        $decision = Authorization::check('posts:publish');

        self::assertSame(DecisionReason::GUARDRAIL, $decision->reason);
        self::assertSame(
            [TraceOutcome::NOT_APPLICABLE, TraceOutcome::REFUSED, TraceOutcome::MATCHED, TraceOutcome::MATCHED],
            \array_map(static fn (TraceEntry $entry): TraceOutcome => $entry->outcome, $decision->trace),
        );
    }

    /**
     * A resource of a tenant is capped by that tenant's guardrails, also when a
     * platform-wide grant admits it from outside the scope and the check is
     * decided at platform scope; a resource of another tenant is not.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheResourcesTenantsGuardrailsCapAResourceAdmittedFromOutsideTheScope(): void
    {
        [$tenantA, $tenantB] = \array_map(static fn (string $id): StubTenant => StubTenant::query()->create(['id' => $id, 'name' => $id]), ['tenant-a', 'tenant-b']);

        $user = StubIdentity::create(['id' => 'user-1']);

        $user->givePermission(Permission::create(['name' => 'posts:delete']));
        $user->givePermission(Permission::create(['name' => 'posts:read']));

        self::guardrails()->set(self::resourcePolicy('b-read-only', [['effect' => 'allow', 'actions' => ['posts:read']]]), $tenantB, ActingContext::for(self::guardrailManager()));

        $this->resolveInTenant($user, $tenantA);

        $inB = ResourceReference::record('posts', '7', Reference::of($tenantB));
        $inA = ResourceReference::record('posts', '8', Reference::of($tenantA));

        $capped = Authorization::check('posts:delete', $inB);

        self::assertSame(DecisionReason::GUARDRAIL, $capped->reason);
        self::assertSame(DecisionStage::GUARDRAIL, $capped->stage);
        self::assertTrue(Authorization::can('posts:read', $inB));
        self::assertTrue(Authorization::can('posts:delete', $inA));
        self::assertTrue(Authorization::can('posts:delete'));
        self::assertSame([$tenantA->getMorphClass(), 'tenant-a'], TenantScope::currentTenant());
    }

    /**
     * A guardrail's deny statement denies at the deny stage whatever allows the
     * action, and a guardrail grants nothing: an action it allows that nothing
     * else allows is denied at the implicit stage.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGuardrailDeniesAtTheDenyStageAndGrantsNothing(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);

        $user->givePermission(Permission::create(['name' => 'posts:delete']));

        self::guardrails()->set(self::resourcePolicy('rail', [
            ['effect' => 'allow', 'actions' => ['posts:*']],
            ['effect' => 'deny', 'actions' => ['posts:delete']],
        ]), null, ActingContext::for(self::guardrailManager()));

        $denied = Authorization::for($user)->check('posts:delete');
        $unheld = Authorization::for($user)->check('posts:read');

        self::assertSame(DecisionReason::EXPLICIT_DENY, $denied->reason);
        self::assertSame(DecisionStage::DENY, $denied->stage);
        self::assertSame(['rail'], \array_map(static fn (StatementReference $statement): string => $statement->policy, $denied->statements));
        self::assertSame(DecisionReason::NO_MATCH, $unheld->reason);
        self::assertSame(DecisionStage::IMPLICIT, $unheld->stage);
        self::assertSame(
            [DecisionStage::DENY, DecisionStage::GUARDRAIL, DecisionStage::BOUNDARY, DecisionStage::SESSION, DecisionStage::ALLOW],
            \array_map(static fn (TraceEntry $entry): DecisionStage => $entry->stage, $unheld->trace),
        );
        self::assertSame(TraceOutcome::MATCHED, $unheld->trace[1]->outcome);
    }

    /**
     * With no guardrail nothing is capped, and the guardrail stage says so.
     *
     * @return void
     */
    public function testNoGuardrailMeansNoCap(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);

        $user->givePermission(Permission::create(['name' => 'posts:edit']));

        $decision = Authorization::for($user)->check('posts:edit');

        self::assertTrue($decision->isAllowed());
        self::assertEquals(new TraceEntry(DecisionStage::GUARDRAIL, TraceOutcome::UNCAPPED), $decision->trace[0]);
        self::assertStringContainsString('[guardrail] guardrails: uncapped', $decision->explain()->toText());
    }

    /**
     * A guardrail whose document cannot be read denies every check in its scope
     * as an invalid policy, rather than lifting the cap.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnUnreadableGuardrailDeniesAsAnInvalidPolicy(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);
        $rail = self::resourcePolicy('rail', [['effect' => 'allow', 'actions' => ['posts:edit']]]);

        $user->givePermission(Permission::create(['name' => 'posts:edit']));
        self::guardrails()->set($rail, null, ActingContext::for(self::guardrailManager()));

        DB::table('policies')->where('id', $rail->getKey())->update(['document' => '{"statements": "broken"}']);

        $decision = Authorization::for($user)->check('posts:edit');

        self::assertSame(DecisionReason::INVALID_POLICY, $decision->reason);
        self::assertSame(DecisionStage::DENY, $decision->stage);
    }

    /**
     * A check of exactly `authorization:guardrail.manage` is exempt from the
     * guardrails: none is read for it, so a guardrail that does not allow it,
     * one that denies it and one that cannot be read leave it allowed, and the
     * guardrail stage records it as exempt. Any other action is still capped,
     * and the subject's own denies and boundaries still count for it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheGuardrailManageCheckIsExemptFromTheGuardrails(): void
    {
        $user = self::guardrailManager();
        $rail = self::resourcePolicy('posts-only', [
            ['effect' => 'allow', 'actions' => ['posts:*']],
            ['effect' => 'deny', 'actions' => [PackagePermissions::GUARDRAIL_MANAGE]],
        ]);

        $user->givePermission(Permission::create(['name' => 'authorization:roles:manage']));
        self::guardrails()->set($rail, null, ActingContext::for($user));
        self::guardrails()->set(self::resourcePolicy('broken', [['effect' => 'allow', 'actions' => ['*']]]), null, ActingContext::for($user));

        DB::table('policies')->where('name', 'broken')->update(['document' => '{"statements": "broken"}']);

        DB::enableQueryLog();
        DB::flushQueryLog();

        $exempt = Authorization::for($user)->check(PackagePermissions::GUARDRAIL_MANAGE);
        $read   = \array_filter(DB::getQueryLog(), static fn (array $query): bool => \str_contains($query['query'], 'guardrails'));

        DB::disableQueryLog();

        self::assertTrue($exempt->isAllowed());
        self::assertSame([], $read);
        self::assertEquals(new TraceEntry(DecisionStage::GUARDRAIL, TraceOutcome::EXEMPT), $exempt->trace[0]);
        self::assertStringContainsString('[guardrail] guardrails: exempt', $exempt->explain()->toText());
        self::assertSame(DecisionReason::INVALID_POLICY, Authorization::for($user)->check('authorization:roles:manage')->reason);

        DB::table('policies')->where('name', 'broken')->update(['document' => '{"statements": []}']);
        $this->app?->forgetInstance(ResolutionCache::class);

        self::assertSame(DecisionReason::GUARDRAIL, Authorization::for($user)->check('authorization:roles:manage')->reason);

        $user->attachPolicy(self::resourcePolicy('no-guardrails', [['effect' => 'deny', 'actions' => [PackagePermissions::GUARDRAIL_MANAGE]]]));

        self::assertSame(DecisionReason::EXPLICIT_DENY, Authorization::for($user)->check(PackagePermissions::GUARDRAIL_MANAGE)->reason);

        $other = self::boundedGuardrailManager();

        self::assertSame(DecisionReason::BOUNDARY, Authorization::for($other)->check(PackagePermissions::GUARDRAIL_MANAGE)->reason);
    }

    /**
     * Setting and removing a guardrail each take effect on the next check
     * through a warm persistent cache, and the next request reads the
     * guardrails from the store, not the database.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testGuardrailChangesInvalidateTheCachedResolution(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app?->make(ConfigRepository::class);
        $config->set('authorization.cache.store', 'array');

        (new AuthorizationServiceProvider($this->container()))->register();

        $user  = StubIdentity::create(['id' => 'user-1']);
        $actor = self::guardrailManager();
        $rail  = self::resourcePolicy('read-cap', [['effect' => 'allow', 'actions' => ['posts:read']]]);
        $check = static fn (): bool => Authorization::for($user)->can('posts:edit');

        $user->givePermission(Permission::create(['name' => 'posts:edit']));

        self::assertTrue($check());

        self::guardrails()->set($rail, null, ActingContext::for($actor));

        self::assertFalse($check());

        $this->app?->forgetInstance(ResolutionCache::class);

        DB::enableQueryLog();
        DB::flushQueryLog();

        self::assertFalse($check());

        $read = \array_filter(DB::getQueryLog(), static fn (array $query): bool => \str_contains($query['query'], 'guardrails'));

        DB::disableQueryLog();

        self::assertSame([], $read);

        self::guardrails()->remove($rail, null, ActingContext::for($actor));

        self::assertTrue($check());
    }

    /**
     * Cold, a check reads every guardrail that applies, the platform's and the
     * tenant chain's, in one query; warm, it reads none, however many checks
     * follow.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testGuardrailsAreReadInOneQueryAndNoneOnceWarm(): void
    {
        [$org, $account] = \array_map(static fn (string $id): StubTenant => StubTenant::query()->create(['id' => $id, 'name' => $id]), ['org', 'account']);

        $this->app?->instance(TenantTree::class, (new StubTenantTree)->put(Reference::of($account), Reference::of($org)));

        $user  = StubIdentity::create(['id' => 'user-1']);
        $actor = self::guardrailManager();

        $user->givePermission(Permission::create(['name' => 'posts:edit']));
        self::guardrails()->set(self::resourcePolicy('account', [['effect' => 'allow', 'actions' => ['posts:edit']]]), $account, ActingContext::for($actor));
        self::guardrails()->set(self::resourcePolicy('org', [['effect' => 'allow', 'actions' => ['posts:*']]]), $org, ActingContext::for($actor));
        self::guardrails()->set(self::resourcePolicy('platform', [['effect' => 'allow', 'actions' => ['posts:*']]]), null, ActingContext::for($actor));

        $this->resolveInTenant($user, $account);
        $this->app?->forgetInstance(ResolutionCache::class);

        DB::enableQueryLog();
        DB::flushQueryLog();

        self::assertTrue(Authorization::can('posts:edit'));

        $cold = \array_filter(DB::getQueryLog(), static fn (array $query): bool => \str_contains($query['query'], 'guardrails'));

        DB::flushQueryLog();

        self::assertTrue(Authorization::can('posts:edit'));
        self::assertFalse(Authorization::can('posts:read'));
        self::assertFalse(Authorization::can('posts:delete'));

        $warm = DB::getQueryLog();

        DB::disableQueryLog();

        self::assertCount(1, $cold);
        self::assertSame([], $warm);
    }

    /**
     * The scopes of the subject's credential cap every check: an action they
     * cover is decided by the grants, and one they do not is denied as
     * `session_policy` at the session stage, the trace naming the credential's
     * cap as refusing it.
     *
     * @return void
     */
    public function testTheCredentialsScopesCapEveryCheck(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);

        $user->givePermission(Permission::create(['name' => 'posts:read']));
        $user->givePermission(Permission::create(['name' => 'posts:edit']));
        $this->withCredential(['posts:read']);

        $read = Authorization::for($user)->check('posts:read');
        $edit = Authorization::for($user)->check('posts:edit');

        self::assertTrue($read->isAllowed());
        self::assertContainsEquals(new TraceEntry(DecisionStage::SESSION, TraceOutcome::COVERED, null, [], 'credential'), $read->trace);
        self::assertSame(DecisionReason::SESSION_POLICY, $edit->reason);
        self::assertSame(DecisionStage::SESSION, $edit->stage);
        self::assertSame([], $edit->statements);
        self::assertEquals(new TraceEntry(DecisionStage::SESSION, TraceOutcome::REFUSED, null, [], 'credential'), $edit->trace[\count($edit->trace) - 1]);
        self::assertStringContainsString('[session] credential: refused', $edit->explain()->toText());
    }

    /**
     * A scope the scope map names stands for its patterns, and a scope it does
     * not name stands for itself as an action or an action pattern.
     *
     * @return void
     */
    public function testTheScopeMapMapsAScopeToItsActions(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);

        foreach (['posts:edit', 'comments:read', 'users:read'] as $name) {
            $user->givePermission(Permission::create(['name' => $name]));
        }

        $this->withCredential(['editor', 'comments:*'], ['editor' => ['posts:edit', 'posts:read']]);

        self::assertTrue(Authorization::for($user)->can('posts:edit'));
        self::assertTrue(Authorization::for($user)->can('comments:read'));
        self::assertSame(DecisionReason::SESSION_POLICY, Authorization::for($user)->check('users:read')->reason);
        self::assertSame(DecisionReason::SESSION_POLICY, Authorization::for($user)->check('editor')->reason);
    }

    /**
     * An explicit cap passed to `capped()` caps the scoped manager's checks
     * alone, and capping a capped manager intersects the caps, the trace naming
     * each cap by its position, outermost first.
     *
     * @return void
     */
    public function testAnExplicitCapCapsTheScopedChecksAndNestedCapsIntersect(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);

        $user->givePermission(Permission::create(['name' => 'posts:*']));

        $outer  = Authorization::for($user)->capped(['posts:*']);
        $nested = $outer->capped(['posts:read', 'comments:read']);

        self::assertTrue($outer->can('posts:edit'));
        self::assertTrue($nested->can('posts:read'));
        self::assertTrue(Authorization::for($user)->can('posts:edit'));

        $denied = $nested->check('posts:edit');

        self::assertSame(DecisionReason::SESSION_POLICY, $denied->reason);
        self::assertEquals(
            [
                new TraceEntry(DecisionStage::SESSION, TraceOutcome::COVERED, null, [], 'capped[1]'),
                new TraceEntry(DecisionStage::SESSION, TraceOutcome::REFUSED, null, [], 'capped[2]'),
            ],
            \array_slice($denied->trace, -2),
        );
        self::assertSame(DecisionReason::SESSION_POLICY, $nested->check('comments:read')->reason);
        self::assertTrue($nested->for($user)->can('posts:read'));
        self::assertFalse($nested->for($user)->can('posts:edit'));
        self::assertFalse(Authorization::capped(['posts:read'])->for($user)->can('posts:edit'));
        self::assertTrue(Authorization::capped(['posts:read'])->for($user)->can('posts:read'));
    }

    /**
     * The credential's cap and an explicit cap intersect: only what both cover
     * passes, whichever of them refuses being named.
     *
     * @return void
     */
    public function testTheCredentialAndAnExplicitCapIntersect(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);

        $user->givePermission(Permission::create(['name' => '*']));
        $this->withCredential(['posts:*']);

        $capped  = Authorization::for($user)->capped(['posts:read', 'comments:read']);
        $edit    = $capped->check('posts:edit');
        $comment = $capped->check('comments:read');

        self::assertTrue($capped->can('posts:read'));
        self::assertSame(DecisionReason::SESSION_POLICY, $edit->reason);
        self::assertEquals(new TraceEntry(DecisionStage::SESSION, TraceOutcome::REFUSED, null, [], 'capped[1]'), $edit->trace[\count($edit->trace) - 1]);
        self::assertSame(DecisionReason::SESSION_POLICY, $comment->reason);
        self::assertContainsEquals(new TraceEntry(DecisionStage::SESSION, TraceOutcome::REFUSED, null, [], 'credential'), $comment->trace);
    }

    /**
     * No cap differs from an empty one: a credential carrying no cap caps
     * nothing, and the session stage says so, while a credential carrying no
     * scopes, or an empty explicit cap, allows nothing.
     *
     * @return void
     */
    public function testNoCapDiffersFromAnEmptyCap(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);

        $user->givePermission(Permission::create(['name' => 'posts:read']));
        $this->withCredential(null);

        $uncapped = Authorization::for($user)->check('posts:read');

        self::assertTrue($uncapped->isAllowed());
        self::assertContainsEquals(new TraceEntry(DecisionStage::SESSION, TraceOutcome::UNCAPPED), $uncapped->trace);
        self::assertSame(DecisionReason::SESSION_POLICY, Authorization::for($user)->capped([])->check('posts:read')->reason);

        $this->withCredential([]);

        self::assertSame(DecisionReason::SESSION_POLICY, Authorization::for($user)->check('posts:read')->reason);
    }

    /**
     * A session cap caps every allow source: a permission held directly or
     * through a role, an identity policy's allow, a role policy's allow, a
     * resource policy's allow naming the subject and a policy override are each
     * denied at the session stage when the cap does not cover the action; and a
     * cap grants nothing, so an action it covers that nothing allows is denied.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionCapBlocksEveryAllowSourceAndGrantsNothing(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);
        $role = Role::create(['name' => 'editor']);
        $post = ResourceReference::record('posts', '7');

        $user->givePermission(Permission::create(['name' => 'posts:edit']));
        $role->givePermission(Permission::create(['name' => 'posts:review']));
        $role->attachPolicy(self::resourcePolicy('role-allow', [['effect' => 'allow', 'actions' => ['posts:archive']]]));
        $user->assignRole($role);
        $user->attachPolicy(self::resourcePolicy('own-allow', [['effect' => 'allow', 'actions' => ['posts:publish']]]));
        $sharing = ['effect' => 'allow', 'actions' => ['posts:delete'], 'principals' => [$user->getMorphClass() . ':user-1']];

        self::attachToResource(self::resourcePolicy('sharing', [$sharing]), ['posts', 7]);

        $capped = Authorization::for($user)->capped(['posts:read']);

        foreach (['posts:edit', 'posts:review', 'posts:archive', 'posts:publish', 'posts:delete'] as $action) {
            $decision = $capped->check($action, $post);

            self::assertSame(DecisionReason::SESSION_POLICY, $decision->reason, $action);
            self::assertSame(DecisionStage::SESSION, $decision->stage, $action);
            self::assertNotContains(DecisionStage::ALLOW, \array_map(static fn (TraceEntry $entry): DecisionStage => $entry->stage, $decision->trace), $action);
            self::assertTrue(Authorization::for($user)->can($action, $post), $action);
        }

        $everything = EvaluationPolicy::fromArray(['name' => 'all', 'statements' => [['effect' => 'allow', 'actions' => ['*']]]]);

        self::assertSame(DecisionReason::SESSION_POLICY, $capped->withPolicies([$everything])->check('posts:edit')->reason);
        self::assertTrue($capped->withPolicies([$everything])->can('posts:read'));
        self::assertSame(DecisionReason::NO_MATCH, $capped->check('posts:read', $post)->reason);
    }

    /**
     * A machine principal without credential scopes is allowed nothing, the
     * default source's included, whatever it holds, and an explicit cap never
     * stands in for its missing scopes; with scopes it is allowed what its
     * grants allow within them, and an explicit cap narrows them further.
     *
     * @return void
     */
    public function testAMachineIsAllowedOnlyWithinItsCredentialsScopes(): void
    {
        $machine = StubMachine::create(['id' => 'svc-1']);

        $machine->givePermission(Permission::create(['name' => 'posts:edit']));
        $machine->givePermission(Permission::create(['name' => 'posts:read']));

        $missing = Authorization::for($machine)->check('posts:edit');

        self::assertSame(DecisionReason::SESSION_POLICY, $missing->reason);
        self::assertSame(DecisionStage::SESSION, $missing->stage);
        self::assertEquals(new TraceEntry(DecisionStage::SESSION, TraceOutcome::REFUSED, null, [], 'credential:missing'), $missing->trace[\count($missing->trace) - 1]);
        self::assertSame(DecisionReason::SESSION_POLICY, Authorization::for($machine)->capped(['posts:edit'])->check('posts:edit')->reason);
        self::assertSame(DecisionReason::SESSION_POLICY, Authorization::for($machine)->capped(['*'])->check('posts:read')->reason);

        $this->withCredential(['posts:*']);

        self::assertTrue(Authorization::for($machine)->can('posts:edit'));
        self::assertTrue(Authorization::for($machine)->capped(['posts:read'])->can('posts:read'));
        self::assertSame(DecisionReason::SESSION_POLICY, Authorization::for($machine)->capped(['posts:read'])->check('posts:edit')->reason);
        self::assertSame(DecisionReason::NO_MATCH, Authorization::for($machine)->check('posts:delete')->reason);

        $this->withCredential([]);

        self::assertSame(DecisionReason::SESSION_POLICY, Authorization::for($machine)->check('posts:edit')->reason);
    }

    /**
     * A person's grants and policies never reach a machine principal whose
     * identity is that person, and a machine's never reach a person whose
     * identity is that machine, however broad the credential's scopes.
     *
     * @return void
     */
    public function testIdentityGrantsNeverCrossBetweenAMachineAndAPerson(): void
    {
        $machine = StubMachine::create(['id' => 'svc-1']);
        $person  = StubIdentity::create(['id' => 'user-1']);

        $person->givePermission(Permission::create(['name' => 'posts:edit']));
        $person->attachPolicy(self::resourcePolicy('person-allow', [['effect' => 'allow', 'actions' => ['posts:publish']]]));
        $machine->givePermission(Permission::create(['name' => 'deploys:run']));

        $this->withCredential(['*']);
        $this->resolveSubject(new Subject($machine, $person));

        self::assertSame(DecisionReason::NO_MATCH, Authorization::check('posts:edit')->reason);
        self::assertSame(DecisionReason::NO_MATCH, Authorization::check('posts:publish')->reason);
        self::assertTrue(Authorization::can('deploys:run'));

        $this->resolveSubject(new Subject($person, $machine));

        self::assertSame(DecisionReason::NO_MATCH, Authorization::check('deploys:run')->reason);
        self::assertTrue(Authorization::can('posts:edit'));
        self::assertTrue(Authorization::can('posts:publish'));
    }

    /**
     * A deny attached to the identity still denies a subject of the other kind,
     * since a deny only narrows a check, and the trace names it at its position
     * in its policy; an allow beside it never allows, whichever way round the
     * machine and the person are.
     *
     * @return void
     */
    public function testACrossKindIdentitysDenyStillDeniesAndItsAllowNeverAllows(): void
    {
        $machine = StubMachine::create(['id' => 'svc-1']);
        $person  = StubIdentity::create(['id' => 'user-1']);
        $mixed   = [['effect' => 'allow', 'actions' => ['posts:publish']], ['effect' => 'deny', 'actions' => ['exports:*']]];
        $denies  = self::resourcePolicy('person-mixed', $mixed);
        $allows  = self::resourcePolicy('machine-mixed', [['effect' => 'allow', 'actions' => ['posts:archive']], ['effect' => 'deny', 'actions' => ['deploys:*']]]);

        $person->attachPolicy($denies);
        $machine->attachPolicy($allows);
        $machine->givePermission(Permission::create(['name' => 'exports:run']));
        $person->givePermission(Permission::create(['name' => 'deploys:run']));

        $this->withCredential(['*']);
        $this->resolveSubject(new Subject($machine, $person));

        $denied = Authorization::check('exports:run');

        self::assertSame(DecisionReason::EXPLICIT_DENY, $denied->reason);
        self::assertEquals([new StatementReference('person-mixed', 1, $denies->id)], $denied->statements);
        self::assertSame(DecisionReason::NO_MATCH, Authorization::check('posts:publish')->reason);
        self::assertTrue(Authorization::can('posts:archive'));

        $this->resolveSubject(new Subject($person, $machine));

        $denied = Authorization::check('deploys:run');

        self::assertSame(DecisionReason::EXPLICIT_DENY, $denied->reason);
        self::assertEquals([new StatementReference('machine-mixed', 1, $allows->id)], $denied->statements);
        self::assertSame(DecisionReason::NO_MATCH, Authorization::check('posts:archive')->reason);
        self::assertTrue(Authorization::can('posts:publish'));
    }

    /**
     * The credential's source is asked once per check, about the check's
     * subject, and a session cap reads nothing from the database: a check a cap
     * covers runs the same queries as one with no cap, and one a cap refuses
     * never reads the permissions.
     *
     * @return void
     */
    public function testASessionCapIsReadOncePerCheckAndAddsNoQuery(): void
    {
        $permission = Permission::create(['name' => 'posts:edit']);
        $users      = [];

        foreach (['warm', 'plain', 'covered', 'refused'] as $id) {
            $users[$id] = StubIdentity::create(['id' => $id]);
            $users[$id]->givePermission($permission);
        }

        $source = $this->withCredential(['posts:*']);
        $counts = [];

        // What every check reads once, whoever it is about, is read first.
        Authorization::for($users['warm'])->check('posts:edit');

        DB::enableQueryLog();

        foreach (['plain' => [], 'covered' => ['posts:edit'], 'refused' => ['posts:read']] as $id => $cap) {
            DB::flushQueryLog();

            $manager = Authorization::for($users[$id]);

            ($cap === [] ? $manager : $manager->capped($cap))->check('posts:edit');

            $counts[$id] = \count(DB::getQueryLog());
        }

        DB::disableQueryLog();

        self::assertSame($counts['plain'], $counts['covered']);
        self::assertLessThan($counts['plain'], $counts['refused']);
        self::assertCount(4, $source->calls);
        self::assertSame($users['refused'], $source->calls[3]->subject);
    }

    /**
     * A permission held allows at the allow stage alone, after every deny and
     * every cap: an explicit deny, a guardrail, a boundary and a session cap
     * each refuse the check before the permission is asked, so the trace has no
     * permission step, and once none refuses, the permission allows, its step
     * naming the held pattern that covers the action.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPermissionHeldAllowsOnlyAfterEveryDenyAndCap(): void
    {
        $user  = StubIdentity::create(['id' => 'user-1']);
        $actor = self::guardrailManager();
        $deny  = self::resourcePolicy('no-editing', [['effect' => 'deny', 'actions' => ['posts:edit']]]);
        $rail  = self::resourcePolicy('read-only', [['effect' => 'allow', 'actions' => ['posts:read']]]);

        $user->givePermission(Permission::create(['name' => 'posts:*']));

        $refused = static function (Decision $decision, DecisionReason $reason, DecisionStage $stage): void {
            self::assertSame($reason, $decision->reason);
            self::assertSame($stage, $decision->stage);
            self::assertNotContains(DecisionStage::ALLOW, \array_map(static fn (TraceEntry $entry): DecisionStage => $entry->stage, $decision->trace));
        };

        $user->attachPolicy($deny);
        $refused(Authorization::for($user)->check('posts:edit'), DecisionReason::EXPLICIT_DENY, DecisionStage::DENY);
        $user->detachPolicy($deny);

        self::guardrails()->set($rail, null, ActingContext::for($actor));
        $refused(Authorization::for($user)->check('posts:edit'), DecisionReason::GUARDRAIL, DecisionStage::GUARDRAIL);
        self::guardrails()->remove($rail, null, ActingContext::for($actor));

        self::boundaries()->set($user, self::resourcePolicy('bounded', [['effect' => 'allow', 'actions' => ['posts:read']]]));
        $refused(Authorization::for($user)->check('posts:edit'), DecisionReason::BOUNDARY, DecisionStage::BOUNDARY);
        self::boundaries()->remove($user);

        $refused(Authorization::for($user)->capped(['posts:read'])->check('posts:edit'), DecisionReason::SESSION_POLICY, DecisionStage::SESSION);

        $allowed = Authorization::for($user)->check('posts:edit');

        self::assertTrue($allowed->isAllowed());
        self::assertSame(DecisionStage::ALLOW, $allowed->stage);
        self::assertEquals([...self::uncapped(), new TraceEntry(DecisionStage::ALLOW, TraceOutcome::HELD, null, [], null, 'posts:*')], $allowed->trace);
        self::assertStringContainsString('[allow] permission "posts:*": held', $allowed->explain()->toText());
    }

    /**
     * A permission held in a tenant allows a check on a resource only where the
     * grant reaches it: in the tenant itself, in a tenant below it only when
     * the grant reaches its subtree, and through an ancestor's grant only when
     * that reaches below; a resource of a sibling, of another tree or of the
     * active tenant's ancestor is denied as `tenant_scope`, and a grant made
     * below the active tenant counts for that tenant's resources alone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPermissionAllowsAResourceOnlyWhereItsGrantReaches(): void
    {
        [$org, $account, $team, $sibling, $other] = $this->tenantTree();

        $user = StubIdentity::create(['id' => 'user-1']);

        foreach (['posts:edit', 'posts:archive', 'posts:read', 'posts:share', 'posts:tag'] as $name) {
            Permission::create(['name' => $name]);
        }

        $user->givePermission('posts:edit', null, $account);
        $user->givePermission('posts:archive', null, $account, false);
        $user->givePermission('posts:read', null, $org);
        $user->givePermission('posts:share', null, $org, false);
        $user->givePermission('posts:tag', null, $team);

        $this->resolveInTenant($user, $account);

        $allows = static fn (string $action, StubTenant $tenant): bool => Authorization::check($action, self::postIn($tenant))->isAllowed();

        self::assertTrue($allows('posts:edit', $account));
        self::assertTrue($allows('posts:edit', $team));
        self::assertTrue($allows('posts:archive', $account));
        self::assertFalse($allows('posts:archive', $team));
        self::assertTrue($allows('posts:read', $account));
        self::assertTrue($allows('posts:read', $team));
        self::assertFalse($allows('posts:share', $account));
        self::assertTrue($allows('posts:tag', $team));
        self::assertFalse($allows('posts:tag', $account));
        self::assertFalse(Authorization::can('posts:tag'));

        foreach ([$sibling, $other, $org] as $tenant) {
            $decision = Authorization::check('posts:edit', self::postIn($tenant));

            self::assertSame(DecisionReason::TENANT_SCOPE, $decision->reason);
            self::assertSame(DecisionStage::TENANT, $decision->stage);
            self::assertSame([], $decision->trace);
        }

        $held = Authorization::check('posts:read', self::postIn($team));

        self::assertEquals(new TraceEntry(DecisionStage::ALLOW, TraceOutcome::HELD, null, [], null, 'posts:read'), $held->trace[\count($held->trace) - 1]);
        self::assertSame([$account->getMorphClass(), 'account'], TenantScope::currentTenant());
    }

    /**
     * A platform-wide grant counts everywhere: it allows a resource of the
     * active tenant and of a tenant below it, admits and allows one of a
     * sibling tenant at platform scope, and allows with no tenant active; a
     * grant in the sibling never admits its resources, and its tenant's
     * guardrails still cap the admitted check.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPlatformWideGrantAllowsEveryResourceWithinItsTenantsCaps(): void
    {
        [, $account, $team, $sibling] = $this->tenantTree();

        $user = StubIdentity::create(['id' => 'user-1']);

        $user->givePermission(Permission::create(['name' => 'posts:edit']));
        $user->givePermission(Permission::create(['name' => 'posts:delete']));
        $user->givePermission(Permission::create(['name' => 'posts:archive']), null, $sibling);

        self::guardrails()->set(self::resourcePolicy('sibling-cap', [['effect' => 'allow', 'actions' => ['posts:edit']]]), $sibling, ActingContext::for(self::guardrailManager()));

        foreach ([$account, null] as $active) {
            $this->resolveInTenant($user, $active);

            foreach ([$account, $team, $sibling] as $tenant) {
                $decision = Authorization::check('posts:edit', self::postIn($tenant));

                self::assertTrue($decision->isAllowed(), Reference::of($tenant)->id);
                self::assertSame('posts:edit', $decision->trace[\count($decision->trace) - 1]->permission);
            }

            self::assertSame(DecisionReason::GUARDRAIL, Authorization::check('posts:delete', self::postIn($sibling))->reason);
            self::assertSame(DecisionReason::TENANT_SCOPE, Authorization::check('posts:archive', self::postIn($sibling))->reason);
        }
    }

    /**
     * A check on a resource with no tenant, a type alone, an opaque identifier
     * or no resource counts the grants that hold in the active tenant, those of
     * the tenant and its ancestors that reach it and platform-wide ones, and
     * never a sibling's; with no tenant active, only platform-wide grants.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantlessCheckCountsOnlyTheGrantsOfTheActiveScope(): void
    {
        [$org, $account, , $sibling] = $this->tenantTree();

        $user = StubIdentity::create(['id' => 'user-1']);

        foreach (['posts:edit', 'posts:archive', 'posts:read', 'posts:share'] as $name) {
            Permission::create(['name' => $name]);
        }

        $user->givePermission('posts:edit', null, $account);
        $user->givePermission('posts:share', null, $org);
        $user->givePermission('posts:archive', null, $sibling);
        $user->givePermission('posts:read');

        $resources = [ResourceReference::record('posts', '7'), ResourceReference::type('posts'), new ResourceReference('opaque-thing'), null];
        $actions   = ['posts:edit', 'posts:archive', 'posts:read', 'posts:share'];
        $allowed   = static fn (): array => \array_map(
            static fn (mixed $resource): array => \array_values(\array_filter($actions, static fn (string $action): bool => Authorization::can($action, $resource))),
            $resources,
        );

        $this->resolveInTenant($user, $account);

        self::assertSame(\array_fill(0, 4, ['posts:edit', 'posts:read', 'posts:share']), $allowed());

        $this->resolveInTenant($user, null);

        self::assertSame(\array_fill(0, 4, ['posts:read']), $allowed());
    }

    /**
     * A grant limited to one application allows only in checks on that
     * application, and an expired grant allows nowhere, for a resource of the
     * tenant as for none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGrantsApplicationAndExpiryHoldForEveryResource(): void
    {
        [, $account] = $this->tenantTree();

        $user = StubIdentity::create(['id' => 'user-1']);
        $post = self::postIn($account);

        $user->givePermission(Permission::create(['name' => 'posts:edit']), null, $account, true, 'admin');
        $user->givePermission(Permission::create(['name' => 'posts:read']), Carbon::now()->addHour(), $account);

        $can = function (string $action, mixed $resource, string $application) use ($user, $account): bool {
            $this->app?->instance(SubjectResolver::class, new StubSubjectResolver($user, $account, $application));
            $this->app?->forgetInstance(ResolvedTenant::class);

            return Authorization::can($action, $resource);
        };

        foreach ([$post, null] as $resource) {
            self::assertTrue($can('posts:edit', $resource, 'admin'));
            self::assertFalse($can('posts:edit', $resource, 'web'));
            self::assertTrue($can('posts:read', $resource, 'web'));
        }

        Carbon::setTestNow(Carbon::now()->addHours(2));

        try {
            foreach ([$post, null] as $resource) {
                self::assertFalse($can('posts:read', $resource, 'web'));
            }
        } finally {
            Carbon::setTestNow();
        }
    }

    /**
     * `permissionsFor()` decides each permission through the decision `check()`
     * makes, so it lists what the decision allows, not what is granted: a
     * permission held that a guardrail caps is not listed, and one held only in
     * another tenant is listed in that tenant alone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testPermissionsForAgreesWithTheDecision(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app?->make(ConfigRepository::class);
        $config->set('authorization.permission_enums', [PermissionEnum::class]);

        [, $account, , $sibling] = $this->tenantTree();

        $user = StubIdentity::create(['id' => 'user-1']);

        $user->givePermission(Permission::create(['name' => PermissionEnum::POSTS_CREATE->value]));
        $user->givePermission(Permission::create(['name' => PermissionEnum::POSTS_DELETE->value]), null, $sibling);

        self::guardrails()->set(self::resourcePolicy('no-create', [['effect' => 'allow', 'actions' => ['posts:delete']]]), $account, ActingContext::for(self::guardrailManager()));

        $expected = [
            'account' => [],
            'sibling' => [PermissionEnum::POSTS_CREATE->value, PermissionEnum::POSTS_DELETE->value],
        ];

        foreach (['account' => $account, 'sibling' => $sibling] as $name => $tenant) {
            $this->resolveInTenant($user, $tenant);

            $listed = Authorization::permissionsFor($user, AuthorizationScope::current());

            self::assertSame($expected[$name], $listed, $name);

            foreach (PermissionEnum::cases() as $case) {
                self::assertSame(Authorization::check($case->value)->isAllowed(), \in_array($case->value, $listed, true), "{$name} {$case->value}");
            }
        }

        self::assertTrue($user->hasPermission(PermissionEnum::POSTS_DELETE->value));
    }

    /**
     * `cannot()`, `any()` and `all()` take every resource form `check()` takes:
     * a model, a `(type, id)` pair, a reference, a model class and an opaque
     * string, each reported by its identifier.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidCheckArgumentException
     */
    public function testCannotAnyAndAllTakeEveryResourceForm(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);
        $post = StubIdentity::create(['id' => 'post-1']);

        $identifiers = [StubIdentity::class . ':post-1', 'posts:7', 'comments:9', StubTenant::class . ':*', 'arn:posts'];
        $policy      = EvaluationPolicy::fromArray(['name' => 'by-identifier', 'statements' => [['effect' => 'allow', 'actions' => ['posts:read'], 'resources' => $identifiers]]]);

        Event::fake([DecisionEvaluated::class]);

        $scope = Authorization::for($user)->withPolicies([$policy]);

        foreach ([$post, ['posts', 7], ResourceReference::record('comments', '9'), StubTenant::class, 'arn:posts'] as $resource) {
            self::assertFalse($scope->cannot('posts:read', $resource));
            self::assertTrue($scope->any(['posts:delete', 'posts:read'], $resource));
            self::assertFalse($scope->all(['posts:read', 'posts:delete'], $resource));
            self::assertTrue($scope->cannot('posts:read', StubIdentity::class . ':post-2'));
        }

        $resources = \array_map(static fn (DecisionEvaluated $event): ?string => $event->resource, self::dispatchedEvents(DecisionEvaluated::class));

        $expected = [];

        foreach ($identifiers as $identifier) {
            $expected = [...$expected, ...\array_fill(0, 5, $identifier), StubIdentity::class . ':post-2'];
        }

        self::assertSame($expected, $resources);
    }

    /**
     * `any()` and `all()` resolve their resource once, however many actions
     * they decide, so a bound resource tenant resolver is asked once.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidCheckArgumentException
     */
    public function testAnyAndAllResolveTheResourceOnce(): void
    {
        $user     = StubIdentity::create(['id' => 'user-1']);
        $model    = StubTenant::create(['id' => 'tenant-a', 'name' => 'Tenant A']);
        $resolver = new FixedResourceTenantResolver;

        $this->app?->instance(ResourceTenantResolver::class, $resolver);

        self::assertFalse(Authorization::for($user)->any(['posts:read', 'posts:edit'], $model));
        self::assertSame([$model], $resolver->asked);

        $user->givePermission(Permission::create(['name' => 'posts:read']));
        $user->givePermission(Permission::create(['name' => 'posts:edit']));

        self::assertTrue(Authorization::for($user)->all(['posts:read', 'posts:edit'], ['posts', 7]));
        self::assertSame([['posts', '7']], $resolver->askedRecords);
    }

    /**
     * An `insufficient_authentication` decision is a refusal for `cannot()`,
     * `any()` and `all()`, which raise no step-up exception, and the last
     * decision keeps its reason.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidCheckArgumentException
     */
    public function testInsufficientAuthenticationIsARefusalForCannotAnyAndAll(): void
    {
        $user    = StubIdentity::create(['id' => '5c1f2e6d-0b7a-4def-9c8b-6a7b8c9d0eb5']);
        $checker = new StubRequirementChecker(RequirementResult::unmet(['multifactor']));
        $manager = $this->inSession($user, 'session-1', $checker)->withPolicies([self::requiringPolicy()]);

        self::assertTrue($manager->cannot('reports:export'));
        self::assertFalse($manager->any(['reports:export']));
        self::assertFalse($manager->all(['reports:export', 'reports:read']));
        self::assertSame(DecisionReason::INSUFFICIENT_AUTHENTICATION, $manager->lastDecision()?->reason);
    }

    /**
     * The facade forwards `cannot()`, `any()` and `all()` to the manager the
     * current request is about.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidCheckArgumentException
     */
    public function testTheFacadeDecidesCannotAnyAndAllForTheCurrentSubject(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);

        $user->givePermission(Permission::create(['name' => 'posts:read']));
        $this->resolvePrincipalAs($user);

        Authorization::clearResolvedInstance('authorization');

        self::assertFalse(Authorization::cannot('posts:read'));
        self::assertTrue(Authorization::cannot('posts:edit'));
        self::assertTrue(Authorization::any(['posts:edit', 'posts:read']));
        self::assertFalse(Authorization::all(['posts:read', 'posts:edit']));
        self::assertSame(DecisionReason::NO_MATCH, Authorization::lastDecision()?->reason);
    }

    /**
     * A query scope is compiled when it is made, so a model it cannot scope is
     * refused at once, and again when it is applied, from the grants then;
     * compiling decides no check, so no decision is recorded or reported.
     *
     * @return void
     */
    public function testAQueryScopeIsCompiledNowAndWhenAppliedRecordingNothing(): void
    {
        Event::fake([DecisionEvaluated::class, AuthorizationFailed::class]);

        $user = StubIdentity::create(['id' => 'user-1']);

        $user->givePermission(Permission::create(['name' => 'posts:view']));
        $this->resolvePrincipalAs($user);
        ScopedPost::query()->create(['title' => 'one']);

        /** @var \SineMacula\Laravel\Authorization\AuthorizationManager $manager */
        $manager = $this->app?->make(AuthorizationManager::class);
        $manager->forgetLastDecision();

        $scope   = $manager->queryScope(new ScopedPost, 'posts:view');
        $builder = ScopedPost::query()->withGlobalScope($scope->identifier, $scope);

        self::assertCount(1, $builder->get());
        self::assertNull($manager->lastDecision());
        Event::assertNotDispatched(DecisionEvaluated::class);

        $user->revokePermission('posts:view');

        self::assertCount(0, $builder->get());

        $this->expectException(QueryScopeRefusedException::class);
        $this->expectExceptionMessage('model_undeclared');

        $manager->queryScope(new StubIdentity, 'posts:view');
    }

    /**
     * `checkMany()` decides each check as `check()` does, keyed and ordered as
     * the checks are, sparse and string keys included, and `check()` decides
     * its one check through it.
     *
     * @return void
     */
    public function testCheckManyDecidesEachCheckAsCheckDoes(): void
    {
        $user = StubIdentity::create(['id' => 'bulk-1']);

        $user->givePermission(Permission::create(['name' => 'posts:read']));

        $manager   = Authorization::for($user);
        $checks    = [7 => new CheckInput('posts:read', 'posts:1'), 'b' => new CheckInput('posts:edit', 'posts:1'), 2 => new CheckInput('posts:read')];
        $decisions = $manager->checkMany($checks);

        self::assertSame([7, 'b', 2], \array_keys($decisions));
        self::assertEquals(\array_map(static fn (CheckInput $check): Decision => $manager->check($check->action, $check->resource, $check->context), $checks), $decisions);
        self::assertSame([], $manager->checkMany([]));
    }

    /**
     * `canEach()` decides every resource, keyed as given, none stopping the
     * rest, a resource repeated included; an insufficient authentication is a
     * refusal; no resource gives none.
     *
     * @return void
     */
    public function testCanEachDecidesEveryResource(): void
    {
        Event::fake([DecisionEvaluated::class]);

        $user    = StubIdentity::create(['id' => '0d6a7f1e-5c2b-4e9a-8f3d-1b2c3d4e5f61']);
        $checker = new StubRequirementChecker(RequirementResult::unmet(['multifactor']));
        $manager = $this->inSession($user, 'session-1', $checker)->withPolicies([self::requiringPolicy()]);
        $allowed = $manager->canEach('reports:export', ['x' => 'reports:1', 3 => 'reports:2', 'again' => 'reports:1']);

        self::assertSame(['x' => false, 3 => false, 'again' => false], $allowed);
        self::assertSame(DecisionReason::INSUFFICIENT_AUTHENTICATION, $manager->lastDecision()?->reason);
        Event::assertDispatchedTimes(DecisionEvaluated::class, 3);
        self::assertSame([], $manager->canEach('reports:export', []));

        $granted = StubIdentity::create(['id' => 'bulk-2']);

        $granted->givePermission(Permission::create(['name' => 'posts:read']));

        $generated = (static function (): \Generator {
            yield 'a' => 'posts:1';
            yield 'b' => 'posts:2';
        })();

        self::assertSame(['a' => true, 'b' => true], Authorization::for($granted)->canEach('posts:read', $generated, ['flag' => 'on']));
        self::assertSame(['a' => false], Authorization::for($granted)->canEach('posts:edit', ['a' => 'posts:1']));
    }

    /**
     * `filterAuthorized()` keeps the resources allowed with their keys, in
     * their order, as given: an array for an array or any other iterable, and a
     * collection of the same class for a collection.
     *
     * @return void
     */
    public function testFilterAuthorizedKeepsTheAllowedResourcesAsGiven(): void
    {
        $user  = StubIdentity::create(['id' => 'bulk-3']);
        $posts = \array_map(static fn (string $title): ScopedPost => ScopedPost::query()->create(['title' => $title]), ['a', 'b', 'c']);

        $user->givePermission(Permission::create(['name' => 'posts:read']));
        self::attachToResource(self::resourcePolicy('deny-b', [['effect' => 'deny', 'actions' => ['posts:read']]]), $posts[1]);

        $manager    = Authorization::for($user);
        $collection = ScopedPost::query()->orderBy('id')->get();
        $filtered   = $manager->filterAuthorized('posts:read', $collection);
        $array      = $manager->filterAuthorized('posts:read', ['z' => $posts[2], 5 => $posts[1], 'y' => $posts[0]]);
        $generated  = $manager->filterAuthorized('posts:read', (static function () use ($posts): \Generator {
            yield 'q' => $posts[1];
            yield 'r' => $posts[2];
        })());

        self::assertInstanceOf($collection::class, $filtered);
        self::assertSame([0, 2], $filtered->keys()->all());
        self::assertSame($collection[0], $filtered[0]);
        self::assertSame(['z' => $posts[2], 'y' => $posts[0]], $array);
        self::assertSame(['r' => $posts[2]], $generated);
        self::assertSame([], $manager->filterAuthorized('posts:read', []));
        self::assertCount(0, $manager->filterAuthorized('posts:read', new Collection));
    }

    /**
     * The facade reaches the bulk checks of the current request's manager.
     *
     * @return void
     */
    public function testTheFacadeReachesTheBulkChecks(): void
    {
        $user = StubIdentity::create(['id' => 'bulk-4']);

        $user->givePermission(Permission::create(['name' => 'posts:read']));
        $this->resolvePrincipalAs($user);

        self::assertTrue(Authorization::checkMany(['one' => new CheckInput('posts:read', 'posts:1')])['one']->isAllowed());
        self::assertSame(['posts:1' => true], Authorization::canEach('posts:read', ['posts:1' => 'posts:1']));
        self::assertSame([1 => 'posts:2'], Authorization::filterAuthorized('posts:read', [1 => 'posts:2']));
    }

    /**
     * Once the package refuses, every operation of a manager obtained while it
     * was healthy refuses by its own guard, before it resolves the subject,
     * reads a cache or the database, or hands over to another operation.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEveryOperationRefusesByItsOwnGuardOnceThePackageRefuses(): void
    {
        $user     = StubIdentity::create(['id' => 'user-1']);
        $manager  = $this->container()->make(AuthorizationManager::class);
        $decision = $manager->check('posts:read');
        $resolved = [];

        $this->refuseThePackage();
        $this->container()->beforeResolving(SubjectResolver::class, static function (string $abstract) use (&$resolved): void {
            $resolved[] = $abstract;
        });

        $this->assertEachRefused([
            'any'               => static fn () => $manager->any(['posts:read'], $user),
            'all'               => static fn () => $manager->all(['posts:read'], $user),
            'authorize'         => static fn () => $manager->authorize('posts:read', $user),
            'furtherChecks'     => static fn () => $manager->furtherChecks(),
            'reportRefusal'     => static fn () => $manager->reportRefusal('posts:read', $user, $decision),
            'check'             => static fn () => $manager->check('posts:read'),
            'check through can' => static fn () => $manager->can('posts:read'),
            'checkMany'         => static fn () => $manager->checkMany([new CheckInput('posts:read')]),
            'canEach'           => static fn () => $manager->canEach('posts:read', [$user]),
            'filterAuthorized'  => static fn () => $manager->filterAuthorized('posts:read', new Collection([$user])),
            'queryScope'        => static fn () => $manager->queryScope($user, 'posts:read'),
            'lastDecision'      => static fn () => $manager->lastDecision(),
            'explain'           => static fn () => $manager->explain('posts:read'),
            'permissionsFor'    => static fn () => $manager->permissionsFor(null, AuthorizationScope::platform()),
            'currentSubject'    => static fn () => $manager->currentSubject(),
        ]);

        self::assertSame([], $resolved);
    }

    /**
     * Assert that exactly one decision event was dispatched, for the check of
     * `posts:create` without a resource, carrying a reference to the supplied
     * principal and the decision's effect, reason and statements, but never the
     * check's context, and that no failure event was dispatched.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $principal
     * @param  \SineMacula\Laravel\Authorization\Evaluation\Decision  $decision
     * @return void
     */
    private static function assertSoleDecisionEvent(Model $principal, Decision $decision): void
    {
        $events = self::dispatchedEvents(DecisionEvaluated::class);

        self::assertCount(1, $events);
        self::assertEquals(Reference::of($principal), $events[0]->subject);
        self::assertSame('posts:create', $events[0]->action);
        self::assertNull($events[0]->resource);
        self::assertSame([$decision->effect, $decision->reason, $decision->statements], [$events[0]->effect, $events[0]->reason, $events[0]->statements]);
        self::assertStringNotContainsString('org-', \serialize($events[0]));
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
     * Bind a session policy source answering every check with the scopes given,
     * or null for no cap, and the scope map given, for the next facade call.
     *
     * @param  list<string>|null  $scopes
     * @param  array<string, list<string>>  $map
     * @return \Tests\Feature\Stubs\StubSessionPolicySource
     */
    private function withCredential(?array $scopes, array $map = []): StubSessionPolicySource
    {
        $source = new StubSessionPolicySource($scopes);

        $this->app?->instance(SessionPolicySource::class, $source);
        $this->container()->make(ConfigRepository::class)->set('authorization.session.scopes', $map);

        foreach (['authorization', AuthorizationManager::class, SessionScopes::class] as $abstract) {
            $this->app?->forgetInstance($abstract);
        }

        Authorization::clearResolvedInstance('authorization');

        return $source;
    }

    /**
     * Resolve the subject given for the next facade call.
     *
     * @param  \SineMacula\Laravel\Authorization\Subject  $subject
     * @return void
     */
    private function resolveSubject(Subject $subject): void
    {
        $this->app?->instance(SubjectResolver::class, new FixedSubjectResolver($subject));
        $this->app?->forgetInstance('authorization');
        $this->app?->forgetInstance(AuthorizationManager::class);

        Authorization::clearResolvedInstance('authorization');
    }

    /**
     * Create a policy of the statements.
     *
     * @param  string  $name
     * @param  list<array<string, mixed>>  $statements
     * @return \SineMacula\Laravel\Authorization\Models\Policy
     */
    private static function resourcePolicy(string $name, array $statements): Policy
    {
        return Policy::create(['name' => $name, 'document' => ['statements' => $statements]]);
    }

    /**
     * Attach the policy to the resource through the resource policy service.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Policy  $policy
     * @param  mixed  $resource
     * @return void
     *
     * @throws \Throwable
     */
    private static function attachToResource(Policy $policy, mixed $resource): void
    {
        $service = ResourcePolicyService::instance();

        self::assertInstanceOf(ResourcePolicyService::class, $service);

        $service->attach($policy, $resource);
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

        $this->container()->instance(SubjectResolver::class, $resolver);
        $this->container()->forgetInstance('authorization');
        $this->container()->forgetInstance(AuthorizationManager::class);
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

    /**
     * Return the steps the guardrail, boundary and session stages add, in that
     * order, when none of them caps the check.
     *
     * @return list<\SineMacula\Laravel\Authorization\Evaluation\TraceEntry>
     */
    private static function uncapped(): array
    {
        return [
            new TraceEntry(DecisionStage::GUARDRAIL, TraceOutcome::UNCAPPED),
            new TraceEntry(DecisionStage::BOUNDARY, TraceOutcome::UNCAPPED),
            new TraceEntry(DecisionStage::SESSION, TraceOutcome::UNCAPPED),
        ];
    }

    /**
     * Resolve the user as the subject, in the tenant, for the next facade call.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $user
     * @param  \Tests\Feature\Stubs\StubTenant|null  $tenant
     * @return void
     */
    private function resolveInTenant(StubIdentity $user, ?StubTenant $tenant): void
    {
        $this->resolvePrincipalAs($user);
        $this->app?->instance(SubjectResolver::class, new StubSubjectResolver($user, $tenant));
        $this->app?->forgetInstance(ResolvedTenant::class);
    }

    /**
     * Create the tenants and bind the tree: the organisation at the top, the
     * account and its sibling below it, the team below the account, and another
     * organisation in a tree of its own.
     *
     * @return list<\Tests\Feature\Stubs\StubTenant>
     */
    private function tenantTree(): array
    {
        $create                           = static fn (string $id): StubTenant => StubTenant::query()->create(['id' => $id, 'name' => $id]);
        $tenants                          = \array_map($create, ['org', 'account', 'team', 'sibling', 'other']);
        [$org, $account, $team, $sibling] = $tenants;

        $this->app?->instance(TenantTree::class, (new StubTenantTree)
            ->put(Reference::of($account), Reference::of($org))
            ->put(Reference::of($team), Reference::of($account))
            ->put(Reference::of($sibling), Reference::of($org)));

        return $tenants;
    }

    /**
     * Return a reference to a post the tenant owns.
     *
     * @param  \Tests\Feature\Stubs\StubTenant  $tenant
     * @return \SineMacula\Laravel\Authorization\Support\ResourceReference
     */
    private static function postIn(StubTenant $tenant): ResourceReference
    {
        return ResourceReference::record('posts', (string) $tenant->getKey(), Reference::of($tenant)); // @phpstan-ignore cast.string
    }

    /**
     * Return the guardrail service, as the container binds it.
     *
     * @return \SineMacula\Laravel\Authorization\Services\GuardrailService
     */
    private static function guardrails(): GuardrailService
    {
        $service = GuardrailService::instance();

        self::assertInstanceOf(GuardrailService::class, $service);

        return $service;
    }

    /**
     * Return an identity that holds the right to manage guardrails
     * platform-wide.
     *
     * @return \Tests\Feature\Stubs\StubIdentity
     */
    private static function guardrailManager(): StubIdentity
    {
        $actor = StubIdentity::create(['id' => 'guardrail-admin']);

        $actor->givePermission(Permission::create(['name' => PackagePermissions::GUARDRAIL_MANAGE]));

        return $actor;
    }

    /**
     * Return an identity that holds the right to manage guardrails
     * platform-wide, under a permission boundary that does not allow it.
     *
     * @return \Tests\Feature\Stubs\StubIdentity
     *
     * @throws \Throwable
     */
    private static function boundedGuardrailManager(): StubIdentity
    {
        $actor = StubIdentity::create(['id' => 'bounded-admin']);

        $actor->givePermission(Permission::query()->firstOrCreate(['name' => PackagePermissions::GUARDRAIL_MANAGE]));
        self::boundaries()->set($actor, self::resourcePolicy('posts-cap', [['effect' => 'allow', 'actions' => ['posts:*']]]));

        return $actor;
    }

    /**
     * Return the boundary service, as the container binds it.
     *
     * @return \SineMacula\Laravel\Authorization\Services\BoundaryService
     */
    private static function boundaries(): BoundaryService
    {
        $service = BoundaryService::instance();

        self::assertInstanceOf(BoundaryService::class, $service);

        return $service;
    }
}
