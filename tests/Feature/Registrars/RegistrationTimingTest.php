<?php

declare(strict_types = 1);

namespace Tests\Feature\Registrars;

use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use Illuminate\Foundation\Application;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Contracts\GrantHook;
use SineMacula\Laravel\Authorization\Contracts\PolicyStore;
use SineMacula\Laravel\Authorization\Contracts\ResourceTenantResolver;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Diagnostics\BindingRegistry;
use SineMacula\Laravel\Authorization\Diagnostics\ContainerState;
use SineMacula\Laravel\Authorization\Diagnostics\DiagnosticMode;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\PackageStatus;
use SineMacula\Laravel\Authorization\Diagnostics\PackageState;
use SineMacula\Laravel\Authorization\Hooks\GrantHooks;
use SineMacula\Laravel\Authorization\Hooks\ListedGrantHooks;
use SineMacula\Laravel\Authorization\Registrars\PendingRegistration;
use SineMacula\Laravel\Authorization\Registrars\SeamBindings;
use SineMacula\Laravel\Authorization\Resolvers\DeclaredResourceTenant;
use SineMacula\Laravel\Authorization\Resolvers\FlatTenantTree;
use Tests\Feature\Stubs\DeferredBindingProvider;
use Tests\Feature\Stubs\FixedResourceTenantResolver;
use Tests\Feature\Stubs\StubPolicyStore;
use Tests\Feature\Stubs\StubTenantTree;
use Tests\Fixtures\Diagnostics\ExplodingTenantTree;
use Tests\Fixtures\Diagnostics\Explosions;
use Tests\Fixtures\GrantHooks\RecordingGrantHook;
use Tests\Fixtures\GrantHooks\RefusingGrantHook;
use Tests\TestCase;

/**
 * Feature tests for when the package's registration steps that may load or run
 * code the configuration names happen: as the application boots, after every
 * provider registered and before any boots, rather than as the package
 * registers, with the outcome binding them at once gave.
 *
 * A binding a sibling makes before the package registers gives way to the class
 * configured, and one it makes after stands; an extender registered after the
 * package's still receives the hook the configured hooks wrap; a deferred
 * provider of the contract is loaded beneath the class configured; and a
 * provider that resolves a seam while it registers gets the package's default.
 * When the application boots for diagnosis on a refused configuration none of
 * these steps run.
 *
 * Each test builds an application of its own, which knows only the
 * configuration it is given, and boots it once every provider registered.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthorizationServiceProvider::class)]
#[CoversClass(SeamBindings::class)]
#[CoversClass(PendingRegistration::class)]
final class RegistrationTimingTest extends TestCase
{
    /**
     * Forget the deferred bindings and the explosions, and restore the suite's
     * application as the container's instance.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        DeferredBindingProvider::$objects = [];
        Explosions::$count                = 0;

        Container::setInstance($this->app);

        parent::tearDown();
    }

    /**
     * A binding a sibling made before the package registered stands until the
     * application boots, and then gives way to the class configured, which is
     * recorded over it.
     *
     * @return void
     */
    public function testABindingMadeBeforeGivesWayAsTheApplicationBoots(): void
    {
        $app     = self::application(['tenant_tree' => StubTenantTree::class]);
        $earlier = static fn (): TenantTree => new FlatTenantTree;

        $app->bind(TenantTree::class, $earlier);

        (new AuthorizationServiceProvider($app))->register();

        self::assertSame($earlier, ContainerState::concrete($app, TenantTree::class));

        $app->boot();

        $record = BindingRegistry::of($app)->get(TenantTree::class);

        self::assertInstanceOf(StubTenantTree::class, $app->make(TenantTree::class));
        self::assertTrue($record?->configured);
        self::assertSame($earlier, $record->earlier);
        self::assertSame(StubTenantTree::class, $record->class);
    }

    /**
     * A binding a sibling makes after the package registered stands over the
     * class configured, which is recorded as bound beneath it.
     *
     * @return void
     */
    public function testABindingMadeAfterStands(): void
    {
        $app = self::application(['tenant_tree' => StubTenantTree::class, 'policy_store' => StubPolicyStore::class]);

        (new AuthorizationServiceProvider($app))->register();

        $app->bind(TenantTree::class, static fn (): TenantTree => new FlatTenantTree);
        $app->instance(PolicyStore::class, $store = self::createStub(PolicyStore::class));

        $app->boot();

        self::assertInstanceOf(FlatTenantTree::class, $app->make(TenantTree::class));
        self::assertSame($store, $app->make(PolicyStore::class));
        self::assertTrue(BindingRegistry::of($app)->get(TenantTree::class)?->configured);
    }

    /**
     * A provider that resolves a seam while it registers gets the package's
     * default, not the class configured, nor the configured hooks; once the
     * application booted the contract resolves to the class configured, with
     * the hooks, and the binding is never taken for the package's default.
     *
     * @return void
     */
    public function testASeamResolvedWhileProvidersRegisterIsThePackagesDefault(): void
    {
        $app = self::application(['tenant_tree' => StubTenantTree::class, 'grant_hooks' => [RecordingGrantHook::class]]);

        (new AuthorizationServiceProvider($app))->register();

        self::assertInstanceOf(FlatTenantTree::class, $app->make(TenantTree::class));
        self::assertInstanceOf(GrantHooks::class, $app->make(GrantHook::class));
        self::assertFalse(AuthorizationServiceProvider::isPackageDefault($app, TenantTree::class));

        $app->boot();

        self::assertInstanceOf(StubTenantTree::class, $app->make(TenantTree::class));
        self::assertInstanceOf(ListedGrantHooks::class, $app->make(GrantHook::class));
        self::assertFalse(AuthorizationServiceProvider::isPackageDefault($app, TenantTree::class));
    }

    /**
     * The configured hooks' extender keeps its place among the contract's
     * extenders: one registered before the package's receives the bound hook,
     * and one registered after, as the providers registered, receives the hook
     * the configured hooks wrap.
     *
     * @return void
     */
    public function testALaterExtenderReceivesTheWrappedHook(): void
    {
        $app      = self::application(['grant_hooks' => [RecordingGrantHook::class]]);
        $received = new \stdClass;

        $app->extend(GrantHook::class, static function (GrantHook $hook) use ($received): GrantHook {
            $received->earlier = $hook;

            return $hook;
        });

        (new AuthorizationServiceProvider($app))->register();

        $app->extend(GrantHook::class, static function (GrantHook $hook) use ($received): GrantHook {
            $received->later = $hook;

            return $hook;
        });

        self::assertCount(2, ContainerState::extenders($app, GrantHook::class));

        $app->boot();

        $resolved = $app->make(GrantHook::class);

        self::assertCount(3, ContainerState::extenders($app, GrantHook::class));
        self::assertInstanceOf(GrantHooks::class, $received->earlier);
        self::assertInstanceOf(ListedGrantHooks::class, $received->later);
        self::assertSame($received->later, $resolved);
    }

    /**
     * A grant hook held as the package registers is wrapped only as the
     * application boots, and the decorator that replaced it is recorded, with
     * the hook it replaced; one held by a provider registering after the
     * package is wrapped then too, and recorded as the later hook it is.
     *
     * @return void
     */
    public function testAHeldGrantHookIsWrappedAsTheApplicationBoots(): void
    {
        $app  = self::application(['grant_hooks' => [RecordingGrantHook::class]]);
        $held = new RefusingGrantHook;

        $app->instance(GrantHook::class, $held);

        (new AuthorizationServiceProvider($app))->register();

        self::assertSame($held, ContainerState::instance($app, GrantHook::class));

        $app->boot();

        $wrapper = ContainerState::instance($app, GrantHook::class);

        self::assertInstanceOf(ListedGrantHooks::class, $wrapper);
        self::assertSame($wrapper, BindingRegistry::of($app)->get(GrantHook::class)?->wrapper);
        self::assertSame($held, BindingRegistry::of($app)->get(GrantHook::class)->earlierInstance);

        self::assertSame($held, BindingRegistry::of($app)->get(GrantHook::class)->wrapped);
        self::assertTrue(BindingRegistry::of($app)->get(GrantHook::class)->isEarlier($wrapper));

        $later = self::application(['grant_hooks' => [RecordingGrantHook::class]]);
        $hook  = new RefusingGrantHook;

        (new AuthorizationServiceProvider($later))->register();

        $later->instance(GrantHook::class, $hook);
        $later->boot();

        $record = BindingRegistry::of($later)->get(GrantHook::class);
        $latest = ContainerState::instance($later, GrantHook::class);

        self::assertNotNull($record);
        self::assertInstanceOf(ListedGrantHooks::class, $latest);
        self::assertSame([$latest, $hook, null], [$record->wrapper, $record->wrapped, $record->earlierInstance]);
        self::assertFalse($record->isEarlier($latest));
        self::assertSame($hook, $record->unwrap($latest));
    }

    /**
     * A deferred provider of a contract the configuration names a class for is
     * loaded as the application boots, not as the package registers, whether
     * the application learned of it before the package registered or after, and
     * the class configured is bound over its binding.
     *
     * @return void
     */
    public function testADeferredSiblingProviderIsLoadedAsTheApplicationBoots(): void
    {
        foreach (['before' => true, 'after' => false] as $when => $isKnownFirst) {
            $app = self::application(['tenant_tree' => StubTenantTree::class]);

            DeferredBindingProvider::$objects = [TenantTree::class => new FlatTenantTree];

            if ($isKnownFirst) {
                $app->addDeferredServices([TenantTree::class => DeferredBindingProvider::class]);
            }

            (new AuthorizationServiceProvider($app))->register();

            if (!$isKnownFirst) {
                $app->addDeferredServices([TenantTree::class => DeferredBindingProvider::class]);
            }

            self::assertFalse($app->providerIsLoaded(DeferredBindingProvider::class), $when);

            $app->boot();

            self::assertTrue($app->providerIsLoaded(DeferredBindingProvider::class), $when);
            self::assertInstanceOf(StubTenantTree::class, $app->make(TenantTree::class), $when);
        }
    }

    /**
     * A binding made after the package registered stands over the class
     * configured when a deferred provider also provides the contract: the
     * provider is loaded beneath it as the application boots, as binding the
     * class at once loaded it before the later binding was made.
     *
     * @return void
     */
    public function testALaterBindingStandsOverADeferredProvidersBinding(): void
    {
        $app   = self::application(['tenant_tree' => StubTenantTree::class]);
        $later = static fn (): TenantTree => new FlatTenantTree;

        DeferredBindingProvider::$objects = [TenantTree::class => new \stdClass];

        $app->addDeferredServices([TenantTree::class => DeferredBindingProvider::class]);

        (new AuthorizationServiceProvider($app))->register();

        $app->singleton(TenantTree::class, $later);
        $app->boot();

        self::assertTrue($app->providerIsLoaded(DeferredBindingProvider::class));
        self::assertSame($later, ContainerState::concrete($app, TenantTree::class));
        self::assertTrue(ContainerState::isShared($app, TenantTree::class));
        self::assertInstanceOf(FlatTenantTree::class, $app->make(TenantTree::class));
    }

    /**
     * The policy store and the resource tenant resolver the configuration names
     * are bound as the application boots, the resolver wrapped in the declared
     * one; the policy store, which has no default, is left unbound until then.
     *
     * @return void
     */
    public function testTheStoreAndResolverConfiguredAreBoundAsTheApplicationBoots(): void
    {
        $app = self::application(['policy_store' => StubPolicyStore::class, 'resource_tenant_resolver' => FixedResourceTenantResolver::class]);

        (new AuthorizationServiceProvider($app))->register();

        self::assertFalse($app->bound(PolicyStore::class));
        self::assertFalse(BindingRegistry::of($app)->get(ResourceTenantResolver::class)?->configured);

        $app->boot();

        $record = BindingRegistry::of($app)->get(ResourceTenantResolver::class);

        self::assertInstanceOf(StubPolicyStore::class, $app->make(PolicyStore::class));
        self::assertInstanceOf(DeclaredResourceTenant::class, $app->make(ResourceTenantResolver::class));
        self::assertTrue($record?->configured);
        self::assertSame(FixedResourceTenantResolver::class, $record->class);
    }

    /**
     * Booting for diagnosis on a refused configuration runs none of the steps:
     * the class configured is neither bound nor built, a deferred provider of
     * its contract is not loaded, a grant hook held is not wrapped, and no seam
     * is resolved.
     *
     * @return void
     */
    public function testARefusedDiagnosisRunsNoStep(): void
    {
        $app  = self::application(['nonsense' => true, 'tenant_tree' => ExplodingTenantTree::class, 'grant_hooks' => [RecordingGrantHook::class]]);
        $held = new RefusingGrantHook;

        DiagnosticMode::enable($app);
        DeferredBindingProvider::$objects = [TenantTree::class => new FlatTenantTree];

        $app->addDeferredServices([TenantTree::class => DeferredBindingProvider::class]);
        $app->instance(GrantHook::class, $held);

        (new AuthorizationServiceProvider($app))->register();

        $app->boot();

        self::assertSame(PackageStatus::REFUSING, PackageState::of($app)?->status());
        self::assertFalse($app->providerIsLoaded(DeferredBindingProvider::class));
        self::assertFalse(BindingRegistry::of($app)->get(TenantTree::class)?->configured);
        self::assertFalse($app->resolved(TenantTree::class));
        self::assertSame($held, ContainerState::instance($app, GrantHook::class));
        self::assertSame(0, Explosions::$count);
        self::assertFalse(PendingRegistration::find($app)?->isPending());
    }

    /**
     * Return a new application holding the authorization configuration given
     * alone.
     *
     * @param  array<string, mixed>  $authorization
     * @return \Illuminate\Foundation\Application
     */
    private static function application(array $authorization): Application
    {
        $app = new Application(\dirname(__DIR__, 3));

        $app->instance('config', new Repository(['authorization' => $authorization]));

        return $app;
    }
}
