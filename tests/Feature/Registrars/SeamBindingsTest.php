<?php

declare(strict_types = 1);

namespace Tests\Feature\Registrars;

use Illuminate\Config\Repository;
use Illuminate\Container\Container;
use Illuminate\Contracts\Foundation\Application as ApplicationContract;
use Illuminate\Foundation\Application;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\Contracts\GrantHook;
use SineMacula\Laravel\Authorization\Hooks\GrantHooks;
use SineMacula\Laravel\Authorization\Hooks\ListedGrantHooks;
use SineMacula\Laravel\Authorization\Registrars\SeamBindings;
use Tests\Feature\Stubs\DeferredBindingProvider;
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
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SeamBindings::class)]
final class SeamBindingsTest extends TestCase
{
    /** @var string The package-owned key that holds the grant hook's default. */
    private const string DEFAULT = 'authorization.default:' . GrantHook::class;

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
     * The contract is bound to the closure the closure handed to the registrar
     * builds for the default's key, so the class that declares it, the service
     * provider in the package, is what a sibling package reads off the binding
     * table, whether the class is the default or a configured one.
     *
     * @param  bool  $configured
     * @return void
     */
    #[DataProvider('configuredProvider')]
    public function testTheContractIsBoundToTheClosureTheRegistrarIsHanded(bool $configured): void
    {
        $app   = self::application();
        $built = [];

        $resolving = static function (string $key) use (&$built): \Closure {
            return $built[$key] = static fn (ApplicationContract $app): mixed => $app->make($key);
        };

        (new SeamBindings($app, $resolving))->bindDefault(GrantHook::class, RecordingGrantHook::class, $configured);

        self::assertSame([self::DEFAULT], \array_keys($built));
        self::assertSame($built[self::DEFAULT], $app->getBindings()[GrantHook::class]['concrete']);
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
     * hands it one.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return \SineMacula\Laravel\Authorization\Registrars\SeamBindings
     */
    private static function seams(Application $app): SeamBindings
    {
        return new SeamBindings($app, static fn (string $key): \Closure => static fn (ApplicationContract $app): mixed => $app->make($key));
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
