<?php

declare(strict_types = 1);

namespace Tests\Feature\Diagnostics;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Foundation\Application;
use Illuminate\Queue\Events\JobProcessed;
use Illuminate\Support\Facades\Blade;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Gate;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Contracts\ActionCatalogue;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationRequirementChecker;
use SineMacula\Laravel\Authorization\Contracts\ConsoleSubjectResolver;
use SineMacula\Laravel\Authorization\Contracts\GrantHook;
use SineMacula\Laravel\Authorization\Contracts\GrantUsageStore;
use SineMacula\Laravel\Authorization\Contracts\IdentityDirectory;
use SineMacula\Laravel\Authorization\Contracts\PolicyResolver;
use SineMacula\Laravel\Authorization\Contracts\PolicyStore;
use SineMacula\Laravel\Authorization\Contracts\ResourceTenantResolver;
use SineMacula\Laravel\Authorization\Contracts\SessionPolicySource;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Diagnostics\BindingRegistry;
use SineMacula\Laravel\Authorization\Diagnostics\Declarations;
use SineMacula\Laravel\Authorization\Diagnostics\DiagnosticMode;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\Origin;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\PackageStatus;
use SineMacula\Laravel\Authorization\Diagnostics\PackageState;
use SineMacula\Laravel\Authorization\Diagnostics\SeamClassifier;
use SineMacula\Laravel\Authorization\Registrars\GateRegistrar;
use SineMacula\Laravel\Authorization\Registrars\QueryScopeRegistrar;
use SineMacula\Laravel\Authorization\Support\DeclaredAbilities;
use SineMacula\Laravel\Authorization\Support\PermissionCatalogue;
use Tests\Feature\Stubs\FixedResourceTenantResolver;
use Tests\Feature\Stubs\RecordingPermissionProvider;
use Tests\Feature\Stubs\StubIdentity;
use Tests\Feature\Stubs\StubPolicyStore;
use Tests\Feature\Stubs\StubSubjectResolver;
use Tests\Fixtures\Diagnostics\ExplodingGrantHook;
use Tests\Fixtures\Diagnostics\ExplodingTenantTree;
use Tests\Fixtures\Diagnostics\Explosions;
use Tests\Fixtures\GrantHooks\RefusingGrantHook;
use Tests\TestCase;

/**
 * Feature tests for an application booted for diagnosis on a refused
 * configuration: registering resolved no seam and ran no code the configuration
 * names, the package's Gate hook is not installed, so its abilities are denied
 * unless the application's own Gate callbacks allow them, usage tracking is not
 * wired, and the Blade directives, the query macro and the middleware aliases
 * stay registered, to refuse when used.
 *
 * The switch is turned on, the configuration set, a grant hook held and every
 * resolution recorded before any provider registers.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthorizationServiceProvider::class)]
#[CoversClass(GateRegistrar::class)]
final class RefusedBootTest extends TestCase
{
    /** @var array<string, mixed> The refused configuration, naming a class for each seam it can and a provider of permissions. */
    private const array CONFIGURATION = [
        'nonsense'                 => true,
        'subject_resolver'         => StubSubjectResolver::class,
        'tenant_tree'              => ExplodingTenantTree::class,
        'resource_tenant_resolver' => FixedResourceTenantResolver::class,
        'policy_store'             => StubPolicyStore::class,
        'grant_hooks'              => [ExplodingGrantHook::class],
        'permission_providers'     => [RecordingPermissionProvider::class],
        'usage'                    => ['enabled' => true],
    ];

    /** @var list<string> What the package must not resolve while it refuses: every seam and every class the configuration names. */
    private const array UNRESOLVED = [
        'authorization', SubjectResolver::class, TenantTree::class, IdentityDirectory::class, GrantHook::class, ConsoleSubjectResolver::class,
        ResourceTenantResolver::class, PolicyStore::class, PolicyResolver::class, ActionCatalogue::class, AuthenticationRequirementChecker::class,
        SessionPolicySource::class, GrantUsageStore::class, PermissionCatalogue::class, DeclaredAbilities::class, StubSubjectResolver::class,
        ExplodingTenantTree::class, FixedResourceTenantResolver::class, StubPolicyStore::class, ExplodingGrantHook::class, RecordingPermissionProvider::class,
    ];

    /** @var list<string> Every abstract the application resolved. */
    private array $resolved = [];

    /** @var \SineMacula\Laravel\Authorization\Contracts\GrantHook|null The grant hook held before the package registers. */
    private ?GrantHook $held = null;

    /**
     * Forget the explosions and permission reads counted.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Explosions::$count                  = 0;
        RecordingPermissionProvider::$reads = 0;

        parent::tearDown();
    }

    /**
     * Registering and booting on a refused configuration resolved none of the
     * seams nor any class the configuration names, built or called no grant
     * hook it lists, left the grant hook held unwrapped and read no permission
     * provider, while the resolutions the boot made, the router's among them,
     * were recorded.
     *
     * @return void
     */
    public function testRegistrationResolvesNoSeamAndRunsNoExtensionCode(): void
    {
        $app = $this->container();

        self::assertSame(PackageStatus::REFUSING, PackageState::of($app)?->status());
        self::assertContains('router', $this->resolved);
        self::assertSame([], \array_values(\array_intersect(self::UNRESOLVED, $this->resolved)));
        self::assertSame(0, Explosions::$count);
        self::assertSame(0, RecordingPermissionProvider::$reads);
        self::assertSame($this->held, $app->make(GrantHook::class));
    }

    /**
     * The policy store the configuration names, which has no default, is left
     * unbound in a refused boot, and reported so.
     *
     * @return void
     */
    public function testThePolicyStoreConfiguredIsLeftUnbound(): void
    {
        $app = $this->container();
        $row = (new SeamClassifier($app, BindingRegistry::of($app), Declarations::of($app)))->classify(PolicyStore::class);

        self::assertFalse($app->bound(PolicyStore::class));
        self::assertSame([Origin::UNBOUND, []], [$row->origin, $row->classes]);
    }

    /**
     * Without the package's Gate hook, Laravel denies an ability the package
     * declares, reading no permission provider to find it; an allow rule the
     * application registers on the Gate stays its own decision, and allows.
     *
     * @return void
     */
    public function testThePackageAbilitiesAreDeniedUnlessTheApplicationAllows(): void
    {
        $user = new StubIdentity(['id' => 'user-1']);

        self::assertFalse(Gate::forUser($user)->allows('reports:export'));
        self::assertSame(0, RecordingPermissionProvider::$reads);

        Gate::before(static fn (): bool => true);

        self::assertTrue(Gate::forUser($user)->allows('reports:export'));
        self::assertSame(0, RecordingPermissionProvider::$reads);
    }

    /**
     * The Blade directives, the query macro and the middleware aliases stay
     * registered, so a view, a builder or a route reaches a refusal, while
     * usage tracking, though turned on, is not wired.
     *
     * @return void
     */
    public function testTheSurfaceStaysRegisteredAndUsageIsNotTracked(): void
    {
        $directives = Blade::getCustomDirectives();
        $middleware = $this->container()->make('router')->getMiddleware();

        foreach (['role', 'endrole', 'permission', 'endunlesspermission'] as $directive) {
            self::assertArrayHasKey($directive, $directives);
        }

        self::assertTrue(Builder::hasGlobalMacro(QueryScopeRegistrar::MACRO));
        self::assertSame(AuthorizationServiceProvider::MIDDLEWARE, \array_intersect_key($middleware, AuthorizationServiceProvider::MIDDLEWARE));
        self::assertFalse(Event::hasListeners(JobProcessed::class));
    }

    /**
     * Forget counts other tests left, turn the switch on, set the refused
     * configuration, hold a grant hook and record every resolution, before any
     * provider registers.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    #[\Override]
    protected function resolveApplicationConfiguration(mixed $app): void
    {
        parent::resolveApplicationConfiguration($app);

        Explosions::$count                  = 0;
        RecordingPermissionProvider::$reads = 0;

        DiagnosticMode::enable($app);

        /** @var \Illuminate\Config\Repository $config */
        $config = $app['config'];

        foreach (self::CONFIGURATION as $key => $value) {
            $config->set("authorization.{$key}", $value);
        }

        $this->held = new RefusingGrantHook;

        $app->instance(GrantHook::class, $this->held);
        $this->record($app);
    }

    /**
     * Record every abstract the application resolves.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return void
     */
    private function record(Application $app): void
    {
        $app->beforeResolving(function (string $abstract): void {
            $this->resolved[] = $abstract;
        });
    }
}
