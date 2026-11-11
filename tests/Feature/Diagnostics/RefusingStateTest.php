<?php

declare(strict_types = 1);

namespace Tests\Feature\Diagnostics;

use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Blade;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Administration\ActingContext;
use SineMacula\Laravel\Authorization\AuthorizationManager;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Config\ConfigValidator;
use SineMacula\Laravel\Authorization\Contracts\ActionCatalogue;
use SineMacula\Laravel\Authorization\Contracts\GrantUsageStore;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Diagnostics\PackageState;
use SineMacula\Laravel\Authorization\Diagnostics\StructuralCheck;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;
use SineMacula\Laravel\Authorization\Facades\Authorization;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Reviews\AccessReview;
use SineMacula\Laravel\Authorization\Reviews\ReviewQuery;
use SineMacula\Laravel\Authorization\Reviews\ReviewScope;
use SineMacula\Laravel\Authorization\Scopes\AuthorizedScope;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Services\ApplicationAccess;
use SineMacula\Laravel\Authorization\Services\BoundaryService;
use SineMacula\Laravel\Authorization\Services\GrantPruner;
use SineMacula\Laravel\Authorization\Services\GrantScopeQuery;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Services\GuardrailService;
use SineMacula\Laravel\Authorization\Services\PermissionService;
use SineMacula\Laravel\Authorization\Services\PolicyService;
use SineMacula\Laravel\Authorization\Services\ResourcePolicyService;
use SineMacula\Laravel\Authorization\Services\RoleService;
use SineMacula\Laravel\Authorization\Support\AuthorizationScope;
use SineMacula\Laravel\Authorization\Support\BladeHelpers;
use SineMacula\Laravel\Authorization\Support\PermissionCatalogue;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResolvedTenant;
use SineMacula\Laravel\Authorization\Usage\GrantUsageRecorder;
use Tests\Feature\Stubs\RecordingPermissionProvider;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubSubjectResolver;
use Tests\TestCase;

/**
 * Feature tests for the refusing state: once the package refuses, every
 * operation of its boundary throws the first refusal before it resolves a seam,
 * reads a cache or the database, or returns early, including through an object
 * obtained while the package was healthy.
 *
 * Each test boots the package healthy, prepares what it needs, then has the
 * package refuse with what the structural check finds in a configuration naming
 * an unknown setting, as the diagnostic boot would.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PackageState::class)]
#[CoversClass(AuthorizationManager::class)]
final class RefusingStateTest extends TestCase
{
    /** @var string The setting the refusal names. */
    private const string REFUSED = 'authorization.nonsense';

    /** @var list<string> The queries run since the package refused. */
    private array $queries = [];

    /** @var list<string> The seams resolved since the package refused. */
    private array $resolved = [];

    /**
     * Forget the permission reads counted.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        RecordingPermissionProvider::$reads = 0;

        parent::tearDown();
    }

    /**
     * Every operation of a manager obtained while the package was healthy, the
     * facade's and a scoped one's included, refuses, before the subject is
     * resolved; a manager built afresh refuses before anything it holds is
     * built.
     *
     * @return void
     */
    public function testTheManagerRefusesEveryOperation(): void
    {
        $user     = StubIdentity::create(['id' => 'user-1']);
        $manager  = $this->container()->make(AuthorizationManager::class);
        $scoped   = $manager->for($user);
        $decision = $manager->check('posts:read');
        $scope    = AuthorizationScope::platform();

        Authorization::getFacadeRoot();

        $this->refuse();

        self::assertEachRefused([
            'can'                => static fn () => $manager->can('posts:read'),
            'cannot'             => static fn () => $manager->cannot('posts:read'),
            'any'                => static fn () => $manager->any([]),
            'all'                => static fn () => $manager->all([]),
            'authorize'          => static fn () => $manager->authorize('posts:read'),
            'check'              => static fn () => $manager->check('posts:read'),
            'checkMany'          => static fn () => $manager->checkMany([]),
            'canEach'            => static fn () => $manager->canEach('posts:read', []),
            'filterAuthorized'   => static fn () => $manager->filterAuthorized('posts:read', []),
            'queryScope'         => static fn () => $manager->queryScope($user, 'posts:read'),
            'explain'            => static fn () => $manager->explain('posts:read'),
            'permissionsFor'     => static fn () => $manager->permissionsFor(null, $scope),
            'heldPermissionsFor' => static fn () => $manager->heldPermissionsFor(null, $scope),
            'furtherChecks'      => static fn () => $manager->furtherChecks(),
            'reportRefusal'      => static fn () => $manager->reportRefusal('posts:read', null, $decision),
            'lastDecision'       => static fn () => $manager->lastDecision(),
            'currentSubject'     => static fn () => $manager->currentSubject(),
            'for'                => static fn () => $manager->for($user),
            'forUser'            => static fn () => $manager->forUser($user),
            'withPolicies'       => static fn () => $manager->withPolicies([]),
            'previewFor'         => static fn () => $manager->previewFor($user),
            'capped'             => static fn () => $manager->capped([]),
            'withoutSessionCaps' => static fn () => $manager->withoutSessionCaps(),
            'a scoped manager'   => static fn () => $scoped->can('posts:read'),
            'the facade'         => static fn () => Authorization::can('posts:read'),
            'a fresh manager'    => function (): mixed {
                $this->container()->forgetInstance('authorization');

                return $this->container()->make('authorization');
            },
        ]);

        $this->assertNothingRead();
    }

    /**
     * The model traits' decisions refuse though the resolution cache holds the
     * answer, and the role's own checks and rank comparisons refuse, reading
     * nothing.
     *
     * @return void
     */
    public function testTheModelTraitsRefuseWithAWarmCache(): void
    {
        [$user, $editor, $viewer] = $this->grantee();

        self::assertTrue($user->hasPermission('posts:read'));
        self::assertTrue($user->hasRole('editor'));
        self::assertSame(['editor'], $user->getRoles());

        $this->refuse();

        self::assertEachRefused([
            'hasPermission'        => static fn () => $user->hasPermission('posts:read'),
            'hasPermissionTo'      => static fn () => $user->hasPermissionTo('posts:read'),
            'getPermissions'       => static fn () => $user->getPermissions(),
            'getPermissionNames'   => static fn () => $user->getPermissionNames(),
            'hasRole'              => static fn () => $user->hasRole('editor'),
            'getRoles'             => static fn () => $user->getRoles(),
            'getRoleNames'         => static fn () => $user->getRoleNames(),
            'getPolicies'          => static fn () => $user->getPolicies(),
            'canActOn'             => static fn () => $user->canActOn($viewer),
            'canEach'              => static fn () => $user->canEach('posts:read', []),
            'filterAuthorized'     => static fn () => $user->filterAuthorized('posts:read', []),
            'permissionsFor'       => static fn () => $user->permissionsFor(AuthorizationScope::platform()),
            'heldPermissionsFor'   => static fn () => $user->heldPermissionsFor(AuthorizationScope::platform()),
            'a role\'s permission' => static fn () => $editor->hasPermission('posts:read'),
            'a role\'s listing'    => static fn () => $editor->getPermissions(),
            'outranks'             => static fn () => $editor->outranks($viewer),
            'outranksOrEquals'     => static fn () => $editor->outranksOrEquals($viewer),
            'isAncestorOf'         => static fn () => $editor->isAncestorOf($viewer),
            'isDescendantOf'       => static fn () => $editor->isDescendantOf($viewer),
        ]);

        $this->assertNothingRead();
    }

    /**
     * The tenant scope refuses on a model's query, as do `within()`, before its
     * callback runs, every getter of the tenant, one held by an enclosing
     * `within()` included, and the resolved tenant's factory and binding, none
     * of them resolving the subject resolver.
     *
     * @return void
     */
    public function testTheTenantScopeAndTheResolvedTenantRefuse(): void
    {
        $resolver = new StubSubjectResolver;
        $held     = TenantScope::within(new Reference('stub_tenant', 'tenant-a'), 'admin', function (): InvalidAuthorizationConfigException {
            $this->refuse();

            return self::refusalOf(TenantScope::currentTenant(...));
        });

        self::assertSame(self::REFUSED, $held->getConfigKey());

        $this->container()->forgetInstance(ResolvedTenant::class);

        self::assertEachRefused([
            'a model query'        => static fn () => Role::query()->count(),
            'within'               => static fn () => TenantScope::within(null, null, static fn () => self::fail('The callback ran.')),
            'currentTenant'        => TenantScope::currentTenant(...),
            'isBelowTenant'        => TenantScope::isBelowTenant(...),
            'currentApplication'   => TenantScope::currentApplication(...),
            'scopeKey'             => TenantScope::scopeKey(...),
            'currentChain'         => TenantScope::currentChain(...),
            'refreshChain'         => TenantScope::refreshChain(...),
            'the factory'          => static fn () => ResolvedTenant::from($resolver),
            'the resolved binding' => fn () => $this->container()->make(ResolvedTenant::class),
        ]);

        $this->assertNothingRead();
    }

    /**
     * A Blade directive in a rendered view, every Blade helper, the query macro
     * and the authorized scope refuse, the directives and the macro still
     * registered.
     *
     * @return void
     */
    public function testBladeAndTheQueryScopesRefuse(): void
    {
        $this->refuse();

        self::assertArrayHasKey('endunlessrole', Blade::getCustomDirectives());

        self::assertEachRefused([
            'a rendered directive'   => static fn () => Blade::render('@role(\'editor\') shown @endrole'),
            'a permission directive' => static fn () => Blade::render('@permission(\'posts:read\') shown @endpermission'),
            'currentSubject'         => BladeHelpers::currentSubject(...),
            'hasRole'                => static fn () => BladeHelpers::hasRole('editor'),
            'hasAllRoles'            => static fn () => BladeHelpers::hasAllRoles([]),
            'hasPermission'          => static fn () => BladeHelpers::hasPermission([]),
            'hasAllPermissions'      => static fn () => BladeHelpers::hasAllPermissions([]),
            'whereAuthorized'        => static fn () => StubIdentity::query()->whereAuthorized('posts:read'),
            'the authorized scope'   => static fn () => (new AuthorizedScope('posts:read'))->apply(StubIdentity::query(), new StubIdentity),
        ]);

        $this->assertNothingRead();
    }

    /**
     * A route through each of the package's middleware refuses before the route
     * runs.
     *
     * @return void
     */
    public function testARouteThroughTheMiddlewareRefuses(): void
    {
        $router = $this->container()->make('router');

        foreach (['role:editor', 'permission:posts:read', 'authorize:posts:read'] as $middleware) {
            $router->get('/refused/' . \strtok($middleware, ':'), static fn (): never => self::fail('The route ran.'))->middleware($middleware);
        }

        $this->refuse();
        $this->withoutExceptionHandling();

        self::assertEachRefused([
            'role'       => fn () => $this->get('/refused/role'),
            'permission' => fn () => $this->get('/refused/permission'),
            'authorize'  => fn () => $this->get('/refused/authorize'),
        ]);

        $this->assertNothingRead();
    }

    /**
     * Application access refuses on the path that allows an application no
     * permission is named for without deciding, every management service
     * refuses before it reads or writes, as a write through a model trait does,
     * and so do the grant scope query, the access reviews and the pruner.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\AuthorizationException
     */
    public function testServicesReviewsAndThePrunerRefuse(): void
    {
        $user     = StubIdentity::create(['id' => 'user-1']);
        $actor    = ActingContext::for($user);
        $policy   = new Policy(['name' => 'unsaved']);
        $unused   = ReviewQuery::unused(ReviewScope::everywhere(), Carbon::now());
        $services = \array_map(fn (string $service): object => $this->container()->make($service), [
            ApplicationAccess::class, RoleService::class, PermissionService::class, PolicyService::class, GrantService::class,
            ResourcePolicyService::class, BoundaryService::class, GuardrailService::class, AccessReview::class, GrantPruner::class, GrantScopeQuery::class,
        ]);

        [$access, $roles, $permissions, $policies, $grants, $resourcePolicies, $boundaries, $guardrails, $review, $pruner, $scopes] = $services;

        $this->refuse();

        self::assertEachRefused([
            'an application named for no permission' => static fn () => $access->mayUse('web', $user, null),
            'a role created'                         => static fn () => $roles->create('editor'),
            'a permission created'                   => static fn () => $permissions->create('posts:read'),
            'a policy listed'                        => static fn () => $policies->list(),
            'a role granted'                         => static fn () => $grants->grantRole($user, 'editor'),
            'a permission given through the trait'   => static fn () => $user->givePermission('posts:read'),
            'resource policies detached'             => static fn () => $resourcePolicies->detachAll($user),
            'boundaries removed'                     => static fn () => $boundaries->removeAll($user),
            'a guardrail removed'                    => static fn () => $guardrails->remove($policy, null, $actor),
            'a review'                               => static fn () => $review->review($unused, $actor),
            'a trusted review'                       => static fn () => $review->trusted($unused),
            'a page'                                 => static fn () => $review->page($unused, $actor),
            'a trusted page'                         => static fn () => $review->trustedPage($unused),
            'a stream'                               => static fn () => $review->stream($unused, $actor),
            'a trusted stream'                       => static fn () => $review->trustedStream($unused),
            'an export'                              => static fn () => $review->export($unused, $actor, static fn (): null => null),
            'a trusted export'                       => static fn () => $review->trustedExport($unused, static fn (): null => null),
            'a prune'                                => static fn () => $pruner->prune(100),
            'an identity\'s grant scope'             => static fn () => $scopes->forIdentity(new Reference('stub_identity', 'user-1'), new Reference('stub_tenant', 't1')),
            'a grant in a tenant'                    => static fn () => $scopes->hasGrantIn($user, new Reference('stub_tenant', 't1')),
        ]);

        $this->assertNothingRead();
    }

    /**
     * The grant usage recorder and the package's usage store refuse when the
     * container builds them, and the permission catalogue, read directly or
     * through the action catalogue, as setting a policy's document on the model
     * does, refuses before any provider declares a permission.
     *
     * @return void
     */
    public function testTheUsageBindingsAndTheCatalogueRefuse(): void
    {
        $app = $this->container();

        $app['config']->set('authorization.permission_providers', [RecordingPermissionProvider::class]);
        $app->forgetInstance(GrantUsageRecorder::class);

        // The suite's permissive action catalogue gives way to the package's.
        $app->forgetExtenders(ActionCatalogue::class);
        $app->forgetScopedInstances();

        $policy   = new Policy(['name' => 'probe']);
        $document = ['version' => 1, 'statements' => [['effect' => 'allow', 'actions' => ['reports:export'], 'resources' => ['*']]]];

        $this->refuse();

        self::assertEachRefused([
            'the recorder'             => static fn () => $app->make(GrantUsageRecorder::class),
            'the store'                => static fn () => $app->make(GrantUsageStore::class),
            'the catalogue'            => static fn () => $app->make(PermissionCatalogue::class)->definitions(),
            'what is declared'         => static fn () => $app->make(PermissionCatalogue::class)->declared(),
            'the action catalogue'     => static fn () => $app->make(ActionCatalogue::class)->covers('reports:*'),
            'a policy\'s document set' => static function () use ($policy, $document): void {
                $policy->document = $document;
            },
        ]);

        self::assertSame(0, RecordingPermissionProvider::$reads);
    }

    /**
     * Once the package's boot threw, outside diagnosis, an application that
     * goes on serving refuses at every entry point, under the fixed reason of a
     * validation that did not finish, rather than running unvalidated: a second
     * command, a model trait's decision with a warm cache, a scoped model's
     * query and a route.
     *
     * @return void
     */
    public function testEveryEntryPointRefusesOnceTheBootThrew(): void
    {
        $app = $this->container();

        [$user] = $this->grantee();

        self::assertTrue($user->hasPermission('posts:read'));

        // Laravel binds a command's closure to the command, so it is not
        // static.
        Artisan::command('probe:decide', fn (): int => Authorization::can('posts:read') ? 0 : 1);
        $app->make('router')->get('/served', static fn (): never => self::fail('The route ran.'))->middleware('permission:posts:read');
        $app['config']->set('authorization.cache.ttl', 0);

        self::assertSame('authorization.cache.ttl', self::refusalOf(static fn () => (new AuthorizationServiceProvider($app))->boot())->getConfigKey());

        $this->withoutExceptionHandling();

        self::assertEachRefused([
            'a second command' => static fn () => Artisan::call('probe:decide'),
            'a warm decision'  => static fn () => $user->hasPermission('posts:read'),
            'a scoped query'   => static fn () => Role::query()->count(),
            'a route'          => fn () => $this->get('/served'),
        ], StructuralCheck::ROOT);
    }

    /**
     * A user holding `posts:read` through the role `editor`, which outranks the
     * role `viewer`; return the user and both roles.
     *
     * @return array{\Tests\Feature\Stubs\StubIdentity, \SineMacula\Laravel\Authorization\Models\Role, \SineMacula\Laravel\Authorization\Models\Role}
     */
    private function grantee(): array
    {
        $user   = StubIdentity::create(['id' => 'user-1']);
        $editor = Role::create(['name' => 'editor', 'rank' => 1]);
        $viewer = Role::create(['name' => 'viewer', 'rank' => 2]);

        Permission::create(['name' => 'posts:read']);

        $editor->givePermission('posts:read');
        $user->assignRole($editor);

        return [$user, $editor, $viewer];
    }

    /**
     * Have the package refuse with what the structural check finds in its
     * configuration with an unknown setting, and count every query run and
     * every subject resolver resolved from then on.
     *
     * @return void
     */
    private function refuse(): void
    {
        $app      = $this->container();
        $findings = ConfigValidator::issues([...$this->authorizationConfig(), 'nonsense' => true], $app);

        PackageState::of($app)?->refuse($findings);

        Event::listen(QueryExecuted::class, function (QueryExecuted $query): void {
            $this->queries[] = $query->sql;
        });

        $app->beforeResolving(SubjectResolver::class, function (string $abstract): void {
            $this->resolved[] = $abstract;
        });
    }

    /**
     * Assert that no query ran and no subject resolver was resolved since the
     * package refused.
     *
     * @return void
     */
    private function assertNothingRead(): void
    {
        self::assertSame([], $this->queries);
        self::assertSame([], $this->resolved);
    }

    /**
     * Assert that each operation refuses, naming the setting given, by default
     * the one refused.
     *
     * @param  array<string, \Closure(): mixed>  $operations
     * @param  string  $path
     * @return void
     */
    private static function assertEachRefused(array $operations, string $path = self::REFUSED): void
    {
        foreach ($operations as $name => $operation) {
            self::assertSame($path, self::refusalOf($operation, $name)->getConfigKey(), $name);
        }
    }

    /**
     * Return the refusal the operation throws, found among the exceptions a
     * rendered view wraps it in.
     *
     * @param  \Closure(): mixed  $operation
     * @param  string  $name
     * @return \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     *
     * @throws \Throwable
     */
    private static function refusalOf(\Closure $operation, string $name = 'the operation'): InvalidAuthorizationConfigException
    {
        try {
            $operation();
        } catch (\Throwable $thrown) {
            for ($exception = $thrown; $exception !== null; $exception = $exception->getPrevious()) {
                if ($exception instanceof InvalidAuthorizationConfigException) {
                    return $exception;
                }
            }

            throw $thrown;
        }

        self::fail("{$name} was not refused.");
    }
}
