<?php

declare(strict_types = 1);

namespace Tests\Feature\PermissionsFor;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\Context\CheckContextFactory;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationRequirementChecker;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Evaluation\CheckBatch;
use SineMacula\Laravel\Authorization\Evaluation\Enums\DecisionReason;
use SineMacula\Laravel\Authorization\Evaluation\Policy as EvaluationPolicy;
use SineMacula\Laravel\Authorization\Events\AuthorizationFailed;
use SineMacula\Laravel\Authorization\Events\DecisionEvaluated;
use SineMacula\Laravel\Authorization\Exceptions\AttributeProviderFailed;
use SineMacula\Laravel\Authorization\Exceptions\InvalidPermissionCatalogueException;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Subject;
use SineMacula\Laravel\Authorization\Support\AuthorizationScope;
use SineMacula\Laravel\Authorization\Support\PackagePermissions;
use SineMacula\Laravel\Authorization\Support\PermissionCatalogue;
use SineMacula\Laravel\Authorization\Support\PermissionDefinition;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResolvedTenant;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use Tests\Concerns\ReadsDispatchedEvents;
use Tests\Feature\Stubs\Enums\CataloguePermission;
use Tests\Feature\Stubs\Enums\IntBackedPermissionEnum;
use Tests\Feature\Stubs\Enums\PermissionEnum;
use Tests\Feature\Stubs\FailingResourceAttributes;
use Tests\Feature\Stubs\FixedSubjectResolver;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubSubjectResolver;
use Tests\Feature\Stubs\StubTenant;
use Tests\Feature\Stubs\StubTenantTree;
use Tests\Fixtures\PermissionsFor\DeclaredPermissions;
use Tests\Fixtures\QueryScoping\InvariantRequirementChecker;
use Tests\TestCase;

/**
 * Feature tests for `permissionsFor()` (AUTHZ-10.4): the actions of the
 * permission catalogue a subject may take in a scope, exactly those `check()`
 * would allow there, listed in the catalogue's order, through the one decision
 * path and recording nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(AuthorizationManager::class)]
#[CoversClass(AuthorizationScope::class)]
#[CoversClass(CheckBatch::class)]
#[CoversClass(PermissionCatalogue::class)]
final class AuthorizationManagerTest extends TestCase
{
    use ReadsDispatchedEvents;

    /** @var string The first action the enum declares. */
    private const string CREATE = 'posts:create';

    /** @var string The second action the enum declares. */
    private const string DELETE = 'posts:delete';

    /**
     * Register the permission enum before each test.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->config()->set('authorization.permission_enums', [PermissionEnum::class]);
    }

    /**
     * A permission held directly or through a role is listed, and one an
     * explicit deny refuses is not.
     *
     * @return void
     */
    public function testGrantsRolesAndDeniesAreWeighedAsTheCheckWeighsThem(): void
    {
        $user = $this->resolve(StubIdentity::create(['id' => 'user-1']));
        $role = Role::create(['name' => 'editor']);

        $role->givePermission(Permission::create(['name' => self::DELETE]));
        $user->assignRole($role);

        self::assertSame([self::DELETE], Authorization::permissionsFor($user, AuthorizationScope::current()));

        $user->givePermission(Permission::create(['name' => self::CREATE]));

        self::assertSame([self::CREATE, self::DELETE], Authorization::permissionsFor($user, AuthorizationScope::current()));

        $user->attachPolicy(Policy::create(['name' => 'no-create', 'document' => ['statements' => [['effect' => 'deny', 'actions' => [self::CREATE]]]]]));

        self::assertSame([self::DELETE], Authorization::permissionsFor($user, AuthorizationScope::current()));
    }

    /**
     * Null is the subject the manager's checks are about, as `check()` takes
     * it: the request's on the facade, the one `for()` names on a scoped
     * manager, and a guest, allowed nothing, on `forUser(null)` or when the
     * request is about no one.
     *
     * @return void
     */
    public function testNullIsTheSubjectTheManagersChecksAreAbout(): void
    {
        $user  = $this->resolve(StubIdentity::create(['id' => 'user-1']));
        $other = StubIdentity::create(['id' => 'user-2']);

        $user->givePermission(Permission::create(['name' => self::CREATE]));
        $other->givePermission(Permission::create(['name' => self::DELETE]));

        self::assertSame([self::CREATE], Authorization::permissionsFor(null, AuthorizationScope::current()));
        self::assertSame([self::CREATE], Authorization::for($user)->permissionsFor(null, AuthorizationScope::current()));
        self::assertSame([self::DELETE], Authorization::for($other)->permissionsFor(null, AuthorizationScope::current()));
        self::assertSame([], Authorization::forUser(null)->permissionsFor(null, AuthorizationScope::current()));

        $this->app?->instance(SubjectResolver::class, new StubSubjectResolver);
        $this->manager();

        self::assertSame([], Authorization::permissionsFor(null, AuthorizationScope::current()));
    }

    /**
     * Null on a manager about the request's subject keeps the request's
     * session, as `check()` does, so an action its session meets the
     * authentication requirement of is listed.
     *
     * @return void
     */
    public function testNullKeepsTheRequestsSession(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);

        $this->app?->instance(AuthenticationRequirementChecker::class, new InvariantRequirementChecker(true));
        $this->app?->instance(SubjectResolver::class, new FixedSubjectResolver(new Subject($user, $user, null, null, 'web', 'session-1')));
        $this->manager();

        $user->attachPolicy(Policy::create(['name' => 'step-up', 'document' => ['statements' => [
            ['effect' => 'allow', 'actions' => [self::CREATE], 'conditions' => ['authentication_requirement' => ['authentication' => ['multifactor' => []]]]],
        ]]]));

        self::assertTrue(Authorization::can(self::CREATE));
        self::assertSame([self::CREATE], Authorization::permissionsFor(null, AuthorizationScope::current()));
        self::assertSame([], Authorization::permissionsFor($user, AuthorizationScope::current()));
    }

    /**
     * A resolved subject is taken as it is, so its session still meets an
     * authentication requirement; the same model named as `for()` names it has
     * no session, its check is `insufficient_authentication`, and the action is
     * not listed.
     *
     * @return void
     */
    public function testAResolvedSubjectKeepsItsSessionAndInsufficientAuthenticationIsNotListed(): void
    {
        $user = StubIdentity::create(['id' => 'user-1']);

        $this->app?->instance(AuthenticationRequirementChecker::class, new InvariantRequirementChecker(true));
        $this->resolve($user);

        $user->attachPolicy(Policy::create(['name' => 'step-up', 'document' => ['statements' => [
            ['effect' => 'allow', 'actions' => [self::CREATE], 'conditions' => ['authentication_requirement' => ['authentication' => ['multifactor' => []]]]],
            ['effect' => 'allow', 'actions' => [self::DELETE]],
        ]]]));

        $subject = new Subject($user, $user, null, null, 'web', 'session-1');

        self::assertSame([self::CREATE, self::DELETE], Authorization::permissionsFor($subject, AuthorizationScope::current()));
        self::assertSame([self::DELETE], Authorization::permissionsFor($user, AuthorizationScope::current()));
        self::assertSame(DecisionReason::INSUFFICIENT_AUTHENTICATION, Authorization::for($user)->check(self::CREATE)->reason);
    }

    /**
     * Any other object is named as `for()` names it: its own grants count, not
     * those of the subject the request is about.
     *
     * @return void
     */
    public function testAModelIsNamedAsForNamesIt(): void
    {
        $user  = $this->resolve(StubIdentity::create(['id' => 'user-1']));
        $other = StubIdentity::create(['id' => 'user-2']);

        $user->givePermission(Permission::create(['name' => self::CREATE]));
        $other->givePermission(Permission::create(['name' => self::DELETE]));

        self::assertSame([self::DELETE], Authorization::permissionsFor($other, AuthorizationScope::current()));
        self::assertSame([self::DELETE], Authorization::for($user)->permissionsFor($other, AuthorizationScope::current()));
        self::assertTrue(Authorization::for($other)->can(self::DELETE));
    }

    /**
     * A tenant other than the request's is listed with that tenant's grants,
     * the platform with platform-wide grants alone, and the request's tenant is
     * back in place afterwards.
     *
     * @return void
     */
    public function testAnotherTenantThanTheRequestsIsListedInThatTenant(): void
    {
        $first  = StubTenant::query()->create(['id' => 't1', 'name' => 't1']);
        $second = StubTenant::query()->create(['id' => 't2', 'name' => 't2']);
        $user   = $this->resolve(StubIdentity::create(['id' => 'user-1']), $first);

        $user->givePermission(Permission::create(['name' => self::CREATE]), null, $first);
        $user->givePermission(Permission::create(['name' => self::DELETE]), null, $second);

        self::assertSame([self::CREATE], Authorization::permissionsFor($user, AuthorizationScope::current()));
        self::assertSame([self::DELETE], Authorization::permissionsFor($user, AuthorizationScope::tenant($second)));
        self::assertSame([self::DELETE], Authorization::permissionsFor($user, AuthorizationScope::tenant(Reference::of($second))));
        self::assertSame([], Authorization::permissionsFor($user, AuthorizationScope::platform()));
        self::assertSame([$first->getMorphClass(), 't1'], TenantScope::currentTenant());
    }

    /**
     * The application limits the grants that count: one made for an application
     * counts on it alone, and with none, only grants for every application
     * count.
     *
     * @return void
     */
    public function testTheApplicationLimitsTheGrantsThatCount(): void
    {
        $user = $this->resolve(StubIdentity::create(['id' => 'user-1']));

        $user->givePermission(Permission::create(['name' => self::CREATE]), null, null, true, 'admin');
        $user->givePermission(Permission::create(['name' => self::DELETE]));

        self::assertSame([self::CREATE, self::DELETE], Authorization::permissionsFor($user, AuthorizationScope::platform('admin')));
        self::assertSame([self::DELETE], Authorization::permissionsFor($user, AuthorizationScope::platform('mobile')));
        self::assertSame([self::DELETE], Authorization::permissionsFor($user, AuthorizationScope::platform()));
    }

    /**
     * A resource of a tenant outside the scope still goes through admission: a
     * grant in the scope's tenant does not reach it, a platform-wide grant
     * does, and the scope's tenant is not replaced by the resource's.
     *
     * @return void
     */
    public function testAResourceOfAnotherTenantStillGoesThroughAdmission(): void
    {
        $first  = StubTenant::query()->create(['id' => 't1', 'name' => 't1']);
        $second = StubTenant::query()->create(['id' => 't2', 'name' => 't2']);
        $user   = $this->resolve(StubIdentity::create(['id' => 'user-1']));

        $user->givePermission(Permission::create(['name' => self::CREATE]), null, $first);
        $user->givePermission(Permission::create(['name' => self::DELETE]));

        $scope   = AuthorizationScope::tenant($first);
        $inside  = ResourceReference::record('posts', 'p1', Reference::of($first));
        $outside = ResourceReference::record('posts', 'p2', Reference::of($second));

        self::assertSame([self::CREATE, self::DELETE], Authorization::permissionsFor($user, $scope));
        self::assertSame([self::CREATE, self::DELETE], Authorization::permissionsFor($user, $scope->withResource($inside)));
        self::assertSame([self::DELETE], Authorization::permissionsFor($user, $scope->withResource($outside)));
        self::assertSame([self::DELETE], Authorization::permissionsFor($user, AuthorizationScope::tenant($second)->withResource($inside)));
    }

    /**
     * Over a tenant tree, a grant reaching a tenant's subtree lists its actions
     * in a descendant tenant, and on a resource of a descendant tenant, but not
     * in a sibling.
     *
     * @return void
     */
    public function testAGrantReachingTheSubtreeIsListedInADescendant(): void
    {
        [$org, $account, $sibling] = \array_map(static fn (string $id): StubTenant => StubTenant::query()->create(['id' => $id, 'name' => $id]), ['org', 'account', 'sibling']);

        $this->app?->instance(TenantTree::class, (new StubTenantTree)->put(Reference::of($account), Reference::of($org)));

        $user = $this->resolve(StubIdentity::create(['id' => 'user-1']));

        $user->givePermission(Permission::create(['name' => self::CREATE]), null, $org, true);

        self::assertSame([self::CREATE], Authorization::permissionsFor($user, AuthorizationScope::tenant($account)));
        $below = ResourceReference::record('posts', 'p1', Reference::of($account));

        self::assertSame([self::CREATE], Authorization::permissionsFor($user, AuthorizationScope::tenant($org)->withResource($below)));
        self::assertSame([], Authorization::permissionsFor($user, AuthorizationScope::tenant($sibling)));
    }

    /**
     * A listing for a resource can differ from the listing for none: an allow
     * restricted to one record lists its action for that record alone.
     *
     * @return void
     */
    public function testAResourceSpecificListingDiffersFromTheGenericOne(): void
    {
        $user = $this->resolve(StubIdentity::create(['id' => 'user-1']));

        $onePost = ['effect' => 'allow', 'actions' => [self::DELETE], 'resources' => ['posts:p1']];

        $user->attachPolicy(Policy::create(['name' => 'one-post', 'document' => ['statements' => [$onePost]]]));

        $scope = AuthorizationScope::current();

        self::assertSame([], Authorization::permissionsFor($user, $scope));
        self::assertSame([self::DELETE], Authorization::permissionsFor($user, $scope->withResource(ResourceReference::record('posts', 'p1'))));
        self::assertSame([], Authorization::permissionsFor($user, $scope->withResource(ResourceReference::record('posts', 'p2'))));
    }

    /**
     * The context is read under `input`, as `check()` reads it.
     *
     * @return void
     */
    public function testTheContextIsReadUnderInput(): void
    {
        $user = $this->resolve(StubIdentity::create(['id' => 'user-1']));

        $flagged = ['effect' => 'allow', 'actions' => [self::CREATE], 'conditions' => ['eq' => ['input.flag' => 'on']]];

        $user->attachPolicy(Policy::create(['name' => 'flagged', 'document' => ['statements' => [$flagged]]]));

        self::assertSame([self::CREATE], Authorization::permissionsFor($user, AuthorizationScope::current(), ['flag' => 'on']));
        self::assertSame([], Authorization::permissionsFor($user, AuthorizationScope::current(), ['flag' => 'off']));
    }

    /**
     * Listing records nothing: the last decision is left as it was, and no
     * `DecisionEvaluated` or `AuthorizationFailed` is dispatched, allowed or
     * refused.
     *
     * @return void
     */
    public function testListingRecordsNothing(): void
    {
        $user = $this->resolve(StubIdentity::create(['id' => 'user-1']));

        $user->givePermission(Permission::create(['name' => self::CREATE]));

        self::assertSame([self::CREATE], Authorization::permissionsFor($user, AuthorizationScope::current()));
        self::assertNull(Authorization::lastDecision());

        $last = Authorization::check(self::DELETE);

        Event::fake([DecisionEvaluated::class, AuthorizationFailed::class]);

        self::assertSame([self::CREATE], Authorization::permissionsFor($user, AuthorizationScope::current()));
        self::assertSame([self::CREATE], Authorization::permissionsFor($user, AuthorizationScope::current()->withResource('posts:p1')));
        self::assertSame($last, Authorization::lastDecision());
        self::assertSame([], self::dispatchedEvents(DecisionEvaluated::class));
        self::assertSame([], self::dispatchedEvents(AuthorizationFailed::class));
    }

    /**
     * An action whose check throws makes the listing throw what it throws,
     * having recorded nothing, and the request's tenant is back in place.
     *
     * @return void
     */
    public function testAFailingAttributeProviderThrowsAndTheScopeIsRestored(): void
    {
        $first    = StubTenant::query()->create(['id' => 't1', 'name' => 't1']);
        $second   = StubTenant::query()->create(['id' => 't2', 'name' => 't2']);
        $user     = $this->resolve(StubIdentity::create(['id' => 'user-1']), $first);
        $provider = new FailingResourceAttributes;

        $this->app?->instance(FailingResourceAttributes::class, $provider);
        $this->config()->set('authorization.attributes.resources', ['posts' => FailingResourceAttributes::class]);

        $policy = EvaluationPolicy::fromArray(['name' => 'status', 'statements' => [
            ['effect' => 'allow', 'actions' => [self::CREATE, self::DELETE], 'conditions' => ['eq' => ['resource.status' => 'published']]],
        ]]);

        $scope = AuthorizationScope::tenant($second)->withResource(ResourceReference::record('posts', 'p1', Reference::of($second)));

        try {
            $this->manager()->withPolicies([$policy])->permissionsFor($user, $scope);

            self::fail('The listing throws.');
        } catch (AttributeProviderFailed $exception) {
            self::assertSame(FailingResourceAttributes::class, $exception->getProvider());
        }

        self::assertSame(1, $provider->calls);
        self::assertNull(Authorization::lastDecision());
        self::assertSame([$first->getMorphClass(), 't1'], TenantScope::currentTenant());
    }

    /**
     * A permission provider that throws makes the listing throw what it throws,
     * before any action is decided.
     *
     * @return void
     */
    public function testAThrowingPermissionProviderThrows(): void
    {
        $user = $this->resolve(StubIdentity::create(['id' => 'user-1']));

        $this->app?->instance(DeclaredPermissions::class, new DeclaredPermissions([], new \RuntimeException('provider down')));
        $this->config()->set('authorization.permission_providers', [DeclaredPermissions::class]);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('provider down');

        Authorization::permissionsFor($user, AuthorizationScope::current());
    }

    /**
     * A catalogue declaring a name twice for the same guard with different
     * metadata cannot be read, and the listing throws
     * `InvalidPermissionCatalogueException`, listing nothing.
     *
     * @return void
     */
    public function testACatalogueThatCannotBeReadThrows(): void
    {
        $user = $this->resolve(StubIdentity::create(['id' => 'user-1']));

        $this->app?->instance(DeclaredPermissions::class, new DeclaredPermissions([new PermissionDefinition(self::CREATE, 'Another description')]));
        $this->config()->set('authorization.permission_providers', [DeclaredPermissions::class]);

        $this->expectException(InvalidPermissionCatalogueException::class);
        $this->expectExceptionMessage('\'posts:create\' is already declared for the same guard with a different description or category.');

        Authorization::permissionsFor($user, AuthorizationScope::current());
    }

    /**
     * The package's permissions, the enums' cases and the providers'
     * definitions are listed in the catalogue's order, each name once, a name
     * declared for two guards included, and only those the check allows.
     *
     * @return void
     */
    public function testTheCatalogueIsListedInItsOrderEachNameOnce(): void
    {
        $user = $this->resolve(StubIdentity::create(['id' => 'user-1']));

        $this->config()->set('authorization.permission_enums', [CataloguePermission::class]);
        $this->config()->set('authorization.permission_providers', [DeclaredPermissions::class]);
        $this->app?->instance(DeclaredPermissions::class, new DeclaredPermissions([
            new PermissionDefinition('reports:view'),
            new PermissionDefinition('posts:archive'),
            new PermissionDefinition('reports:view', null, null, 'api'),
        ]));

        $user->givePermission(Permission::create(['name' => '*']));

        $everything = [PackagePermissions::GUARDRAILS_MANAGE, 'posts:create', 'posts.publish', 'posts:archive', 'reports:view'];

        self::assertSame($everything, Authorization::permissionsFor($user, AuthorizationScope::current()));

        $user->attachPolicy(Policy::create(['name' => 'no-posts', 'document' => ['statements' => [['effect' => 'deny', 'actions' => ['posts:*']]]]]));

        self::assertSame([PackagePermissions::GUARDRAILS_MANAGE, 'posts.publish', 'reports:view'], Authorization::permissionsFor($user, AuthorizationScope::current()));
    }

    /**
     * An entry of the configured enums the boot validation would refuse is
     * skipped by the catalogue, as it is read after boot, rather than failing
     * mid-request.
     *
     * @return void
     */
    public function testAnEnumEntryTheValidationWouldRefuseIsSkipped(): void
    {
        $user = $this->resolve(StubIdentity::create(['id' => 'user-1']));

        $user->givePermission(Permission::create(['name' => self::CREATE]));

        $this->config()->set('authorization.permission_enums', [123, \stdClass::class, ['nested'], null, IntBackedPermissionEnum::class]);

        self::assertSame([], Authorization::permissionsFor($user, AuthorizationScope::current()));

        $this->config()->set('authorization.permission_enums', [IntBackedPermissionEnum::class, PermissionEnum::class]);

        self::assertSame([self::CREATE], Authorization::permissionsFor($user, AuthorizationScope::current()));
    }

    /**
     * Resolve the request about the user, in the tenant or none, and make the
     * manager afresh.
     *
     * @param  \Tests\Feature\Stubs\StubIdentity  $user
     * @param  \Tests\Feature\Stubs\StubTenant|null  $tenant
     * @return \Tests\Feature\Stubs\StubIdentity
     */
    private function resolve(StubIdentity $user, ?StubTenant $tenant = null): StubIdentity
    {
        $this->app?->instance(SubjectResolver::class, new StubSubjectResolver($user, $tenant));
        $this->app?->forgetInstance(ResolvedTenant::class);
        $this->manager();

        return $user;
    }

    /**
     * Return a manager made afresh, reading the bindings as they are now, and
     * make the facade resolve it.
     *
     * @return \SineMacula\Laravel\Authorization\AuthorizationManager
     */
    private function manager(): AuthorizationManager
    {
        $this->app?->forgetInstance('authorization');
        $this->app?->forgetInstance(AuthorizationManager::class);
        $this->app?->forgetInstance(CheckContextFactory::class);

        Authorization::clearResolvedInstance('authorization');

        /** @var \SineMacula\Laravel\Authorization\AuthorizationManager */
        return $this->app?->make('authorization');
    }

    /**
     * Return the configuration repository.
     *
     * @return \Illuminate\Config\Repository
     */
    private function config(): ConfigRepository
    {
        /** @var \Illuminate\Config\Repository */
        return $this->app?->make(ConfigRepository::class);
    }
}
