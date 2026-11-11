<?php

declare(strict_types = 1);

namespace Tests\Feature\Registrars;

use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use Illuminate\Contracts\Foundation\Application as ApplicationContract;
use Illuminate\Foundation\Application;
use Illuminate\Support\Arr;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Config\ConfigValidator;
use SineMacula\Laravel\Authorization\Context\DeclaredContextKeyCatalogue;
use SineMacula\Laravel\Authorization\Contracts\AuthenticationRequirementChecker;
use SineMacula\Laravel\Authorization\Contracts\ContextKeyCatalogue;
use SineMacula\Laravel\Authorization\Contracts\GrantHook;
use SineMacula\Laravel\Authorization\Contracts\IdentityDirectory;
use SineMacula\Laravel\Authorization\Contracts\PolicyStore;
use SineMacula\Laravel\Authorization\Contracts\ResourceTenantResolver;
use SineMacula\Laravel\Authorization\Contracts\SessionPolicySource;
use SineMacula\Laravel\Authorization\Contracts\SubjectResolver;
use SineMacula\Laravel\Authorization\Contracts\TenantTree;
use SineMacula\Laravel\Authorization\Diagnostics\BindingRegistry;
use SineMacula\Laravel\Authorization\Diagnostics\ContainerState;
use SineMacula\Laravel\Authorization\Diagnostics\CurrentBinding;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;
use SineMacula\Laravel\Authorization\Hooks\GrantHooks;
use SineMacula\Laravel\Authorization\Hooks\ListedGrantHooks;
use SineMacula\Laravel\Authorization\Registrars\PendingRegistration;
use SineMacula\Laravel\Authorization\Registrars\SeamBindings;
use SineMacula\Laravel\Authorization\Resolvers\AuthGuardSubjectResolver;
use SineMacula\Laravel\Authorization\Resolvers\DeclaredResourceTenant;
use SineMacula\Laravel\Authorization\Resolvers\FlatTenantTree;
use SineMacula\Laravel\Authorization\Resolvers\GuardUserIdentityDirectory;
use SineMacula\Laravel\Authorization\Resolvers\NoResourceTenant;
use SineMacula\Laravel\Authorization\Resolvers\NoSessionPolicy;
use SineMacula\Laravel\Authorization\Resolvers\RefusingRequirementChecker;
use Tests\Feature\Stubs\DeferredBindingProvider;
use Tests\Feature\Stubs\FixedResourceTenantResolver;
use Tests\Feature\Stubs\StubPolicyStore;
use Tests\Feature\Stubs\StubSubjectResolver;
use Tests\Feature\Stubs\StubTenantTree;
use Tests\Fixtures\GrantHooks\RecordingGrantHook;
use Tests\Fixtures\GrantHooks\RefusingGrantHook;
use Tests\TestCase;

/**
 * Feature tests for the seam bindings: the package's default of a contract,
 * scoped under its package-owned key and giving way to a binding made before
 * the package registers or after (N103); the class the configuration names,
 * bound over an earlier binding and a deferred provider's (N106); and the grant
 * hooks the configuration lists, extended around the bound hook (N108).
 *
 * Each test binds the grant hook contract in an application of its own, which
 * knows only the configuration it is given.
 *
 * A seam setting read while the package registers, before the configuration is
 * validated, that names no class implementing the contract binds the package's
 * default as though nothing were configured, so registering never fails and
 * leaves the bindings as nothing configured would, and the boot refuses the
 * setting, naming it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SeamBindings::class)]
#[CoversClass(AuthorizationServiceProvider::class)]
final class SeamBindingsTest extends TestCase
{
    /** @var string The package-owned key that holds the grant hook's default. */
    private const string DEFAULT = 'authorization.default:' . GrantHook::class;

    /** @var array<class-string, class-string> The class each seam's package-owned key builds when nothing is configured. */
    private const array DEFAULTS = [
        SubjectResolver::class                  => AuthGuardSubjectResolver::class,
        TenantTree::class                       => FlatTenantTree::class,
        IdentityDirectory::class                => GuardUserIdentityDirectory::class,
        ResourceTenantResolver::class           => NoResourceTenant::class,
        AuthenticationRequirementChecker::class => RefusingRequirementChecker::class,
        SessionPolicySource::class              => NoSessionPolicy::class,
    ];

    /**
     * Forget the deferred bindings and restore the suite's application as the
     * container's instance.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        DeferredBindingProvider::$objects = [];

        Container::setInstance($this->app);

        parent::tearDown();
    }

    /**
     * The default is held under its package-owned key, scoped to the job, and
     * the contract resolves to it when nothing else is bound.
     *
     * @return void
     */
    public function testTheDefaultIsScopedUnderItsKey(): void
    {
        $app = self::application();

        self::seams($app)->bindDefault(GrantHook::class, RecordingGrantHook::class);

        $first = $app->make(GrantHook::class);

        self::assertInstanceOf(RecordingGrantHook::class, $first);
        self::assertSame($first, $app->make(self::DEFAULT));
        self::assertSame($first, $app->make(GrantHook::class));

        $app->forgetScopedInstances();

        self::assertNotSame($first, $app->make(GrantHook::class));
    }

    /**
     * The default is bound through the closure the closure handed to the
     * registrar builds for the default's key, so the class that declares it,
     * the service provider in the package, is what a sibling package reads off
     * the binding table.
     *
     * @return void
     */
    public function testTheDefaultIsBoundToTheClosureTheRegistrarIsHanded(): void
    {
        $app   = self::application();
        $built = [];

        $resolving = static function (string $key) use (&$built): \Closure {
            return $built[$key] = static fn (ApplicationContract $app): mixed => $app->make($key);
        };

        (new SeamBindings($app, $resolving))->bindDefault(GrantHook::class, RecordingGrantHook::class);

        self::assertSame([self::DEFAULT], \array_keys($built));
        self::assertSame($built[self::DEFAULT], $app->getBindings()[GrantHook::class]['concrete']);
        self::assertInstanceOf(RecordingGrantHook::class, $app->make(GrantHook::class));
    }

    /**
     * A configured class is bound through a closure the registrar declares
     * itself, never the one it is handed, so neither the provider nor a sibling
     * package takes the application's choice for the package's default and
     * replaces it.
     *
     * @return void
     */
    public function testAConfiguredClassIsNotBoundToTheClosureTheRegistrarIsHanded(): void
    {
        $app   = self::application();
        $built = [];

        $resolving = static function (string $key) use (&$built): \Closure {
            return $built[$key] = static fn (ApplicationContract $app): mixed => $app->make($key);
        };

        (new SeamBindings($app, $resolving))->bindDefault(GrantHook::class, RecordingGrantHook::class, true);

        $concrete = $app->getBindings()[GrantHook::class]['concrete'];

        self::assertSame([], $built);
        self::assertSame(SeamBindings::class, (new \ReflectionFunction($concrete))->getClosureScopeClass()?->getName());
        self::assertInstanceOf(RecordingGrantHook::class, $app->make(GrantHook::class));
    }

    /**
     * The default gives way to a binding made before or after it, and stays
     * reachable under its key.
     *
     * @return void
     */
    public function testTheDefaultGivesWayToAnyOtherBinding(): void
    {
        $app     = self::application();
        $earlier = new RefusingGrantHook;
        $later   = new RefusingGrantHook;

        $app->instance(GrantHook::class, $earlier);

        self::seams($app)->bindDefault(GrantHook::class, RecordingGrantHook::class);

        self::assertSame($earlier, $app->make(GrantHook::class));
        self::assertInstanceOf(RecordingGrantHook::class, $app->make(self::DEFAULT));

        $app->bind(GrantHook::class, static fn (): GrantHook => $later);

        self::assertSame($later, $app->make(GrantHook::class));
    }

    /**
     * A configured class replaces a binding made before it, and gives way to
     * one made after.
     *
     * @return void
     */
    public function testAConfiguredClassReplacesOnlyAnEarlierBinding(): void
    {
        $app   = self::application();
        $later = new RefusingGrantHook;

        $app->instance(GrantHook::class, new RefusingGrantHook);

        self::seams($app)->bindDefault(GrantHook::class, RecordingGrantHook::class, true);

        self::assertInstanceOf(RecordingGrantHook::class, $app->make(GrantHook::class));

        $app->instance(GrantHook::class, $later);

        self::assertSame($later, $app->make(GrantHook::class));
    }

    /**
     * Provide whether the binding is of a configured class, and whether the
     * deferred provider is then loaded as the package registers.
     *
     * @return iterable<string, array{bool}>
     */
    public static function configuredProvider(): iterable
    {
        yield 'a configured class' => [true];
        yield 'the default' => [false];
    }

    /**
     * A deferred provider the application knows of is loaded, and its binding
     * replaced, for a configured class; for the default it stays deferred, and
     * its binding stands once the contract is resolved.
     *
     * @param  bool  $configured
     * @return void
     */
    #[DataProvider('configuredProvider')]
    public function testADeferredProviderIsLoadedOnlyForAConfiguredClass(bool $configured): void
    {
        $app   = self::application();
        $bound = self::defer($app);

        self::seams($app)->bindDefault(GrantHook::class, RecordingGrantHook::class, $configured);

        self::assertSame($configured, $app->providerIsLoaded(DeferredBindingProvider::class));

        self::assertSame(DeferredBindingProvider::class, BindingRegistry::of($app)->get(GrantHook::class)?->deferredProvider);

        $resolved = $app->make(GrantHook::class);

        self::assertSame($configured, $resolved instanceof RecordingGrantHook);
        self::assertSame(!$configured, $resolved === $bound);
    }

    /**
     * A deferred provider the application learns of after the seam was bound,
     * as it learns of those of its configuration and of package discovery, is
     * loaded, and its binding replaced, as the application boots.
     *
     * @return void
     */
    public function testADeferredProviderLearnedOfLaterIsReplacedAsTheApplicationBoots(): void
    {
        $app = self::application();

        self::seams($app)->bindDefault(GrantHook::class, RecordingGrantHook::class, true);

        self::defer($app);

        $app->boot();

        self::assertTrue($app->providerIsLoaded(DeferredBindingProvider::class));
        self::assertInstanceOf(RecordingGrantHook::class, $app->make(GrantHook::class));
    }

    /**
     * Without a deferred provider, a binding made after a configured class
     * still stands once the application boots.
     *
     * @return void
     */
    public function testALaterBindingStandsOnceTheApplicationBoots(): void
    {
        $app   = self::application();
        $later = new RefusingGrantHook;

        self::seams($app)->bindDefault(GrantHook::class, RecordingGrantHook::class, true);

        $app->instance(GrantHook::class, $later);
        $app->boot();

        self::assertSame($later, $app->make(GrantHook::class));
    }

    /**
     * Provide what the configuration key names: a class other than the default,
     * the default, or nothing, whether the class replaces an earlier binding,
     * and the class the default's key then holds.
     *
     * @return iterable<string, array{array<string, class-string>, bool, class-string}>
     */
    public static function configurationProvider(): iterable
    {
        yield 'another class' => [['hook' => RefusingGrantHook::class], true, RefusingGrantHook::class];
        yield 'the default' => [['hook' => RecordingGrantHook::class], false, RecordingGrantHook::class];
        yield 'nothing' => [[], false, RecordingGrantHook::class];
    }

    /**
     * A class the configuration key names in place of the default replaces an
     * earlier binding; naming the default, or nothing, leaves it standing, and
     * the default's key holds the class named, else the default.
     *
     * @param  array<string, class-string>  $authorization
     * @param  bool  $replaces
     * @param  class-string  $class
     * @return void
     */
    #[DataProvider('configurationProvider')]
    public function testTheConfigurationKeyNamesTheClass(array $authorization, bool $replaces, string $class): void
    {
        $app     = self::application($authorization);
        $earlier = new RefusingGrantHook;

        $app->instance(GrantHook::class, $earlier);

        self::seams($app)->bindConfigured(GrantHook::class, 'authorization.hook', RecordingGrantHook::class);

        self::assertSame(!$replaces, $app->make(GrantHook::class) === $earlier);
        self::assertInstanceOf($class, $app->make(self::DEFAULT));
    }

    /**
     * With nothing configured and nothing bound, the contract resolves to the
     * default.
     *
     * @return void
     */
    public function testWithNothingConfiguredTheDefaultIsBound(): void
    {
        $app = self::application();

        self::seams($app)->bindConfigured(GrantHook::class, 'authorization.hook', RecordingGrantHook::class);

        self::assertInstanceOf(RecordingGrantHook::class, $app->make(GrantHook::class));
    }

    /**
     * With no hook listed the grant hook's default holds none, and a hook bound
     * before stands alone; with hooks listed the bound hook is wrapped.
     *
     * @return void
     */
    public function testTheListedGrantHooksAreExtendedAroundTheBoundHook(): void
    {
        $app     = self::application(['grant_hooks' => []]);
        $earlier = new RefusingGrantHook;

        self::seams($app)->bindGrantHooks();

        $default = $app->make(GrantHook::class);

        self::assertInstanceOf(GrantHooks::class, $default);
        self::assertTrue($default->isEmpty());

        $app = self::application();

        $app->instance(GrantHook::class, $earlier);

        self::seams($app)->bindGrantHooks();

        self::assertSame($earlier, $app->make(GrantHook::class));

        $app = self::application(['grant_hooks' => [RecordingGrantHook::class]]);

        self::seams($app)->bindGrantHooks();

        self::assertInstanceOf(ListedGrantHooks::class, $app->make(GrantHook::class));
    }

    /**
     * The class a configuration key names is returned when it exists and
     * implements the contract; for anything else the default is, null among the
     * defaults.
     *
     * @return void
     */
    public function testTheConfiguredClassIsOnlyOneImplementingTheContract(): void
    {
        foreach ([null, 42, '', [RefusingGrantHook::class], 'App\Missing\Hook', \stdClass::class, GrantHook::class] as $value) {
            $seams = self::seams(self::application(['hook' => $value]));

            self::assertSame(RecordingGrantHook::class, $seams->configuredClass('authorization.hook', GrantHook::class, RecordingGrantHook::class));
            self::assertNull($seams->configuredClass('authorization.hook', GrantHook::class, null));
        }

        $seams = self::seams(self::application(['hook' => RefusingGrantHook::class]));

        self::assertSame(RefusingGrantHook::class, $seams->configuredClass('authorization.hook', GrantHook::class, RecordingGrantHook::class));
        self::assertSame(RecordingGrantHook::class, self::seams(self::application())->configuredClass('authorization.hook', GrantHook::class, RecordingGrantHook::class));
    }

    /**
     * Provide every seam the configuration names a class for while the package
     * registers, with a value naming no class implementing its contract.
     *
     * @return iterable<string, array{class-string, string, mixed}>
     */
    public static function malformedSeamProvider(): iterable
    {
        $seams = [
            SubjectResolver::class                  => 'subject_resolver',
            TenantTree::class                       => 'tenant_tree',
            IdentityDirectory::class                => 'identity_directory',
            ResourceTenantResolver::class           => 'resource_tenant_resolver',
            AuthenticationRequirementChecker::class => 'requirement_checker',
            SessionPolicySource::class              => 'session.source',
            PolicyStore::class                      => 'policy_store',
        ];

        $values = ['null' => null, 'an int' => 42, 'an empty string' => '', 'an array' => ['App\Seam'], 'no class' => 'App\Missing\Seam', 'another class' => \stdClass::class];

        foreach ($seams as $contract => $key) {
            foreach ($values as $name => $value) {
                if ($contract === PolicyStore::class && $value === null) {
                    continue;
                }

                yield "{$key} as {$name}" => [$contract, $key, $value];
            }
        }
    }

    /**
     * Registering with a malformed seam setting does not fail, and, once the
     * application boots, binds the package's default as when nothing is
     * configured: the contract resolves through the package's own closure,
     * which a sibling package replaces, and a policy store is not bound at all.
     *
     * @param  class-string  $contract
     * @param  string  $key
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('malformedSeamProvider')]
    public function testAMalformedSeamBindsTheDefault(string $contract, string $key, mixed $value): void
    {
        $app = self::registered(self::malformed($key, $value));

        $app->boot();

        if ($contract === PolicyStore::class) {
            self::assertFalse($app->bound(PolicyStore::class));

            return;
        }

        self::assertTrue(AuthorizationServiceProvider::isPackageDefault($app, $contract));
        self::assertSame(self::DEFAULTS[$contract], self::defaultClassOf($app, $contract));
    }

    /**
     * A binding a sibling package made before the package registered stands
     * over a malformed seam setting, as it does over no setting, and one made
     * after replaces the default.
     *
     * @param  class-string  $contract
     * @param  string  $key
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('malformedSeamProvider')]
    public function testASiblingsBindingStandsInEitherOrder(string $contract, string $key, mixed $value): void
    {
        $before  = self::application(self::malformed($key, $value));
        $earlier = self::createStub($contract);

        $before->instance($contract, $earlier);

        (new AuthorizationServiceProvider($before))->register();

        self::assertSame($earlier, $before->make($contract));

        $after = self::registered(self::malformed($key, $value));
        $later = self::createStub($contract);

        $after->instance($contract, $later);

        self::assertSame($later, $after->make($contract));
    }

    /**
     * A deferred provider of the contract stays deferred over a malformed seam
     * setting, and its binding stands once the contract is resolved.
     *
     * @param  class-string  $contract
     * @param  string  $key
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('malformedSeamProvider')]
    public function testADeferredProviderStaysDeferred(string $contract, string $key, mixed $value): void
    {
        $app   = self::application(self::malformed($key, $value));
        $bound = self::createStub($contract);

        DeferredBindingProvider::$objects = [$contract => $bound];

        $app->addDeferredServices([$contract => DeferredBindingProvider::class]);

        (new AuthorizationServiceProvider($app))->register();

        self::assertFalse($app->providerIsLoaded(DeferredBindingProvider::class));
        self::assertSame($bound, $app->make($contract));
    }

    /**
     * A binding already resolved before the package registers is neither
     * replaced nor rebound over a malformed seam setting.
     *
     * @param  class-string  $contract
     * @param  string  $key
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('malformedSeamProvider')]
    public function testAnAlreadyResolvedBindingIsLeftAlone(string $contract, string $key, mixed $value): void
    {
        $app      = self::application(self::malformed($key, $value));
        $resolved = self::createStub($contract);
        $rebound  = new \ArrayObject;

        $app->singleton($contract, static fn (): object => $resolved);
        $app->make($contract);
        $app->rebinding($contract, static function () use ($rebound): void {
            $rebound->append(true);
        });

        (new AuthorizationServiceProvider($app))->register();

        self::assertSame($resolved, $app->make($contract));
        self::assertCount(0, $rebound);
    }

    /**
     * The boot refuses a malformed seam setting, naming its path.
     *
     * @param  class-string  $contract
     * @param  string  $key
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('malformedSeamProvider')]
    public function testTheBootRefusesAMalformedSeam(string $contract, string $key, mixed $value): void
    {
        $config = $this->authorizationConfig();

        Arr::set($config, $key, $value);

        try {
            ConfigValidator::validate($config, $this->container());

            self::fail("A malformed {$contract} was accepted.");
        } catch (InvalidAuthorizationConfigException $exception) {
            self::assertSame("authorization.{$key}", $exception->getConfigKey());
        }
    }

    /**
     * Registering with grant hooks that are not a list extends nothing, and the
     * boot refuses them, naming the setting.
     *
     * @return void
     */
    public function testMalformedGrantHooksExtendNothing(): void
    {
        foreach ([null, RecordingGrantHook::class, 5] as $hooks) {
            $app = self::registered(['grant_hooks' => $hooks]);

            self::assertInstanceOf(GrantHooks::class, $app->make(GrantHook::class));

            $config                = $this->authorizationConfig();
            $config['grant_hooks'] = $hooks;

            try {
                ConfigValidator::validate($config, $this->container());

                self::fail('Malformed grant hooks were accepted.');
            } catch (InvalidAuthorizationConfigException $exception) {
                self::assertSame('authorization.grant_hooks', $exception->getConfigKey());
            }
        }
    }

    /**
     * Each binding is recorded before it is made: what was bound already, the
     * closure the package binds, the key it forwards to and the class it
     * builds; a binding made before stands, and the record keeps it.
     *
     * @return void
     */
    public function testEachBindingIsRecordedBeforeItIsMade(): void
    {
        $app     = self::application();
        $earlier = new RefusingGrantHook;

        $app->instance(GrantHook::class, $earlier);

        self::seams($app)->bindDefault(GrantHook::class, RecordingGrantHook::class);

        $record = BindingRegistry::of($app)->get(GrantHook::class);

        self::assertNotNull($record);
        self::assertSame($earlier, $record->earlierInstance);
        self::assertNull($record->earlier);
        self::assertNull($record->deferredProvider);
        self::assertNull($record->wrapper);
        self::assertSame(self::DEFAULT, $record->target);
        self::assertSame(RecordingGrantHook::class, $record->class);
        self::assertFalse($record->configured);
        self::assertTrue($record->wasBound());
        self::assertSame($earlier, $app->make(GrantHook::class));
    }

    /**
     * A shared binding resolved before the package binds the contract is
     * recorded by both its closure and what it built, either of which the
     * report matches.
     *
     * @return void
     */
    public function testAResolvedSharedBindingIsRecordedByItsClosureAndInstance(): void
    {
        foreach (['singleton', 'scoped'] as $kind) {
            $app     = self::application();
            $earlier = static fn (): RefusingGrantHook => new RefusingGrantHook;

            if ($kind === 'singleton') {
                $app->singleton(GrantHook::class, $earlier);
            } else {
                $app->scoped(GrantHook::class, $earlier);
            }

            $built = $app->make(GrantHook::class);

            self::seams($app)->bindDefault(GrantHook::class, RecordingGrantHook::class);

            $record = BindingRegistry::of($app)->get(GrantHook::class);

            self::assertNotNull($record, $kind);
            self::assertSame($earlier, $record->earlier, $kind);
            self::assertSame($built, $record->earlierInstance, $kind);
            self::assertTrue($record->isEarlier(CurrentBinding::of($app, GrantHook::class)->supplier()), $kind);
            self::assertSame($built, $app->make(GrantHook::class), $kind);
        }
    }

    /**
     * The grant hook held as an instance as the package registers is wrapped at
     * once by the configured hooks, and the decorator that replaced it is
     * recorded; an instance that is no grant hook is left as it is, and nothing
     * is recorded of a decorator.
     *
     * @return void
     */
    public function testTheDecoratorReplacingAHeldGrantHookIsRecorded(): void
    {
        $app     = self::application(['grant_hooks' => [RecordingGrantHook::class]]);
        $earlier = new RefusingGrantHook;

        $app->instance(GrantHook::class, $earlier);

        self::seams($app)->bindGrantHooks();

        $record  = BindingRegistry::of($app)->get(GrantHook::class);
        $wrapper = ContainerState::instance($app, GrantHook::class);

        self::assertNotNull($record);
        self::assertInstanceOf(ListedGrantHooks::class, $wrapper);
        self::assertSame($wrapper, $record->wrapper);
        self::assertSame($earlier, $record->earlierInstance);

        $app   = self::application(['grant_hooks' => [RecordingGrantHook::class]]);
        $other = new \stdClass;

        $app->instance(GrantHook::class, $other);

        self::seams($app)->bindGrantHooks();

        self::assertSame($other, ContainerState::instance($app, GrantHook::class));
        self::assertNull(BindingRegistry::of($app)->get(GrantHook::class)?->wrapper);

        $app = self::application(['grant_hooks' => [RecordingGrantHook::class]]);

        self::seams($app)->bindGrantHooks();

        self::assertNull(BindingRegistry::of($app)->get(GrantHook::class)?->wrapper);
    }

    /**
     * A configured class is recorded with its key, and the closure recorded is
     * the one the contract is bound to; a seam built with a closure records the
     * class it names.
     *
     * @return void
     */
    public function testAConfiguredBindingIsRecordedWithItsKey(): void
    {
        $app = self::application();

        self::seams($app)->bindDefault(GrantHook::class, static fn (): GrantHook => new RecordingGrantHook, true, 'authorization.example', RecordingGrantHook::class);

        $record = BindingRegistry::of($app)->get(GrantHook::class);

        self::assertNotNull($record);
        self::assertSame($app->getBindings()[GrantHook::class]['concrete'], $record->binding);
        self::assertSame('authorization.example', $record->configKey);
        self::assertSame(RecordingGrantHook::class, $record->class);
        self::assertTrue($record->configured);
        self::assertFalse($record->wasBound());
    }

    /**
     * A seam built once per application is bound only when nothing is bound to
     * it yet, and recorded with no key to forward to.
     *
     * @return void
     */
    public function testASharedSeamIsBoundIfUnboundAndRecorded(): void
    {
        $app     = self::application();
        $earlier = static fn (): RefusingGrantHook => new RefusingGrantHook;

        $app->singleton(GrantHook::class, $earlier);

        self::seams($app)->bindSharedIf(GrantHook::class, static fn (): GrantHook => new RecordingGrantHook, RecordingGrantHook::class);

        $record = BindingRegistry::of($app)->get(GrantHook::class);

        self::assertNotNull($record);
        self::assertNull($record->target);
        self::assertSame($earlier, $record->earlier);
        self::assertNull($record->earlierInstance);
        self::assertInstanceOf(RefusingGrantHook::class, $app->make(GrantHook::class));
        self::assertSame(DeclaredContextKeyCatalogue::class, BindingRegistry::of(self::registered([]))->get(ContextKeyCatalogue::class)?->class);
    }

    /**
     * A setting naming the default class with a leading backslash or in another
     * case names the default: an instance handed over before the package
     * registers stands, as it does when nothing is configured, where binding a
     * configured class would have dropped it.
     *
     * @return void
     */
    public function testTheDefaultNamedAnotherWayLeavesAnEarlierBindingStanding(): void
    {
        foreach (['\\' . FlatTenantTree::class, \strtoupper(FlatTenantTree::class), '\\' . NoResourceTenant::class] as $named) {
            $app     = self::application(['tenant_tree' => $named, 'resource_tenant_resolver' => $named]);
            $earlier = new \stdClass;

            $app->instance(TenantTree::class, $earlier);
            $app->instance(ResourceTenantResolver::class, $earlier);

            (new AuthorizationServiceProvider($app))->register();

            $contract = \str_contains($named, 'NoResourceTenant') ? ResourceTenantResolver::class : TenantTree::class;

            self::assertSame($earlier, ContainerState::instance($app, $contract), $named);
            self::assertFalse(BindingRegistry::of($app)->get($contract)?->configured, $named);
        }
    }

    /**
     * Handed the steps left to the boot, the registrar binds the class the
     * configuration names only once they run: until then the contract resolves
     * the default through a closure the registrar declares, so a sibling
     * reading the binding table leaves it, and the record holds the default.
     *
     * @return void
     */
    public function testHandedTheStepsAConfiguredClassIsBoundAsTheyRun(): void
    {
        $app     = self::application(['tenant_tree' => StubTenantTree::class, 'policy_store' => StubPolicyStore::class]);
        $pending = new PendingRegistration;
        $seams   = self::seams($app, $pending);

        $seams->bindConfigured(TenantTree::class, 'authorization.tenant_tree', FlatTenantTree::class);
        $seams->bindConfigured(PolicyStore::class, 'authorization.policy_store', null);

        $before  = BindingRegistry::of($app)->get(TenantTree::class);
        $default = $app->make(TenantTree::class);

        self::assertSame(SeamBindings::class, self::declaringClassOf($app, TenantTree::class));
        self::assertInstanceOf(FlatTenantTree::class, $default);
        self::assertFalse($before?->configured);
        self::assertFalse($app->bound(PolicyStore::class));
        self::assertTrue($pending->isPending());

        $pending->run();

        $after = BindingRegistry::of($app)->get(TenantTree::class);

        self::assertInstanceOf(StubTenantTree::class, $app->make(TenantTree::class));
        self::assertInstanceOf(StubPolicyStore::class, $app->make(PolicyStore::class));
        self::assertTrue($after?->configured);
    }

    /**
     * Handed the steps, a configured name that turns out to name no class
     * implementing the contract binds the default through the closure built for
     * the default's key once they run, as when nothing is configured, and binds
     * no policy store at all, before they run or after, its record showing no
     * class configured.
     *
     * @return void
     */
    public function testHandedTheStepsAMalformedNameBindsTheDefaultAsTheyRun(): void
    {
        $app     = self::application(['tenant_tree' => 'App\Missing\Tree', 'policy_store' => \stdClass::class]);
        $pending = new PendingRegistration;
        $seams   = self::seams($app, $pending);

        $seams->bindConfigured(TenantTree::class, 'authorization.tenant_tree', FlatTenantTree::class);
        $seams->bindConfigured(PolicyStore::class, 'authorization.policy_store', null);

        self::assertFalse($app->bound(PolicyStore::class));
        self::assertNotNull(BindingRegistry::of($app)->get(PolicyStore::class));

        $pending->run();

        self::assertSame(self::class, self::declaringClassOf($app, TenantTree::class));
        self::assertFalse(BindingRegistry::of($app)->get(TenantTree::class)?->configured);
        self::assertSame($app->getBindings()[TenantTree::class]['concrete'], BindingRegistry::of($app)->get(TenantTree::class)->binding);
        self::assertInstanceOf(FlatTenantTree::class, $app->make(TenantTree::class));
        self::assertFalse($app->bound(PolicyStore::class));
        self::assertFalse(BindingRegistry::of($app)->get(PolicyStore::class)->configured);
    }

    /**
     * Handed the steps, the grant hooks the configuration lists are extended
     * around the bound hook only once they run.
     *
     * @return void
     */
    public function testHandedTheStepsTheGrantHooksAreExtendedAsTheyRun(): void
    {
        $app     = self::application(['grant_hooks' => [RecordingGrantHook::class]]);
        $pending = new PendingRegistration;

        self::seams($app, $pending)->bindGrantHooks();

        self::assertSame([], ContainerState::extenders($app, GrantHook::class));

        $pending->run();

        self::assertInstanceOf(ListedGrantHooks::class, $app->make(GrantHook::class));
    }

    /**
     * Handed the steps, the extender running the listed hooks keeps the place
     * it had among the contract's extenders as the package registered: after
     * one registered before, which receives the bound hook, and before one
     * registered after, which receives the wrapped hook.
     *
     * @return void
     */
    public function testHandedTheStepsTheGrantHooksExtenderKeepsItsPlace(): void
    {
        $app      = self::application(['grant_hooks' => [RecordingGrantHook::class]]);
        $pending  = new PendingRegistration;
        $received = [];
        $record   = static function (string $when) use (&$received): \Closure {
            return static function (GrantHook $hook) use ($when, &$received): GrantHook {
                $received[$when] = $hook;

                return $hook;
            };
        };

        $app->extend(GrantHook::class, $record('earlier'));

        self::seams($app, $pending)->bindGrantHooks();

        $app->extend(GrantHook::class, $record('later'));

        $pending->run();

        $resolved = $app->make(GrantHook::class);

        self::assertCount(3, ContainerState::extenders($app, GrantHook::class));
        self::assertInstanceOf(GrantHooks::class, $received['earlier'] ?? null);
        self::assertInstanceOf(ListedGrantHooks::class, $received['later'] ?? null);
        self::assertSame($received['later'], $resolved);
    }

    /**
     * Handed the steps, an instance or an alias a provider puts on a contract
     * the configuration names a class for, after the package registered, stands
     * once they run, as a binding made afterwards does.
     *
     * @return void
     */
    public function testHandedTheStepsALaterInstanceOrAliasStands(): void
    {
        $tree = new FlatTenantTree;
        $made = [
            'an instance' => static fn (Application $app) => $app->instance(TenantTree::class, $tree),
            'an alias'    => static function (Application $app) use ($tree): void {
                $app->instance('acme.tree', $tree);
                $app->alias('acme.tree', TenantTree::class);
            },
        ];

        foreach ($made as $kind => $make) {
            $app     = self::application(['tenant_tree' => StubTenantTree::class]);
            $pending = new PendingRegistration;

            self::seams($app, $pending)->bindConfigured(TenantTree::class, 'authorization.tenant_tree', FlatTenantTree::class);

            $make($app);
            $pending->run();

            self::assertSame($tree, $app->make(TenantTree::class), $kind);
            self::assertTrue(BindingRegistry::of($app)->get(TenantTree::class)?->configured, $kind);
        }
    }

    /**
     * The resource tenant resolver, the default or a class configured, is
     * wrapped in the declared resolver the provider builds around it.
     *
     * @return void
     */
    public function testTheResourceTenantResolverIsBuiltByTheBuilderGiven(): void
    {
        foreach ([[], ['resource_tenant_resolver' => FixedResourceTenantResolver::class]] as $authorization) {
            $app = self::registered($authorization);

            $app->boot();

            self::assertInstanceOf(DeclaredResourceTenant::class, $app->make(ResourceTenantResolver::class));
        }
    }

    /**
     * Return the class that declares the closure the contract is bound to.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @param  class-string  $contract
     * @return string|null
     */
    private static function declaringClassOf(Application $app, string $contract): ?string
    {
        $concrete = $app->getBindings()[$contract]['concrete'] ?? null;

        self::assertInstanceOf(\Closure::class, $concrete);

        return (new \ReflectionFunction($concrete))->getClosureScopeClass()?->getName();
    }

    /**
     * Return the authorization configuration setting the seam's key to the
     * value, its subject resolver the stub, so nothing else resolves the
     * application's guard.
     *
     * @param  string  $key
     * @param  mixed  $value
     * @return array<string, mixed>
     */
    private static function malformed(string $key, mixed $value): array
    {
        $authorization = ['subject_resolver' => StubSubjectResolver::class];

        Arr::set($authorization, $key, $value);

        return $authorization;
    }

    /**
     * Return a new application holding the authorization configuration given,
     * the package registered in it.
     *
     * @param  array<string, mixed>  $authorization
     * @return \Illuminate\Foundation\Application
     */
    private static function registered(array $authorization): Application
    {
        $app = self::application($authorization);

        (new AuthorizationServiceProvider($app))->register();

        return $app;
    }

    /**
     * Return the class the package-owned key of the contract builds, as the
     * binding holds it, without building it.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @param  class-string  $contract
     * @return mixed
     */
    private static function defaultClassOf(Application $app, string $contract): mixed
    {
        $concrete = $app->getBindings()["authorization.default:{$contract}"]['concrete'] ?? null;

        self::assertInstanceOf(\Closure::class, $concrete);

        $variables = (new \ReflectionFunction($concrete))->getClosureUsedVariables();

        return $variables['concrete'] ?? $variables['class'] ?? null;
    }

    /**
     * Return a new application holding the authorization configuration given
     * alone, set as the container's instance.
     *
     * @param  array<string, mixed>  $authorization
     * @return \Illuminate\Foundation\Application
     */
    private static function application(array $authorization = []): Application
    {
        $app = new Application(\dirname(__DIR__, 3));

        $app->instance('config', new Repository(['authorization' => $authorization]));

        return $app;
    }

    /**
     * Return the registrar of the seams in the application, handed a closure
     * building the closure each contract is bound to, as the service provider
     * hands it one, and, when given, the steps left to the boot.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @param  \SineMacula\Laravel\Authorization\Registrars\PendingRegistration|null  $later
     * @return \SineMacula\Laravel\Authorization\Registrars\SeamBindings
     */
    private static function seams(Application $app, ?PendingRegistration $later = null): SeamBindings
    {
        return new SeamBindings($app, static fn (string $key): \Closure => static fn (ApplicationContract $app): mixed => $app->make($key), $later);
    }

    /**
     * Have a deferred provider bind a hook on the contract, as a sibling
     * package would, tell the application of it, and return the hook.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return \SineMacula\Laravel\Authorization\Contracts\GrantHook
     */
    private static function defer(Application $app): GrantHook
    {
        $bound = new RefusingGrantHook;

        DeferredBindingProvider::$objects = [GrantHook::class => $bound];

        $app->addDeferredServices([GrantHook::class => DeferredBindingProvider::class]);

        return $bound;
    }
}
