<?php

declare(strict_types = 1);

namespace Tests\Feature\Hooks;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Contracts\GrantHook;
use SineMacula\Laravel\Authorization\Exceptions\GrantRefusedException;
use SineMacula\Laravel\Authorization\Hooks\GrantHooks;
use SineMacula\Laravel\Authorization\Hooks\GrantWidening;
use SineMacula\Laravel\Authorization\Hooks\ListedGrantHooks;
use SineMacula\Laravel\Authorization\Registrars\SeamBindings;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Feature\Stubs\DeferredBindingProvider;
use Tests\Fixtures\GrantHooks\RecordingGrantHook;
use Tests\Fixtures\GrantHooks\RefusingGrantHook;
use Tests\Fixtures\GrantHooks\SecondGrantHook;
use Tests\TestCase;

/**
 * Feature tests for the hooks the configuration lists, run before whatever the
 * grant hook contract resolves to (N108).
 *
 * The package extends the contract, so the listed hooks run first, in order,
 * then the hook bound on it, however and whenever that was bound: before the
 * package registered or after, with `bind()`, `singleton()` or `scoped()`, by a
 * deferred provider, decorated by an earlier extender, or the package's
 * default, and any of them may refuse. A hook already wrapped is not wrapped
 * again, and the listed hooks run once for each call however many decorators
 * are nested, so the grant service may wrap the hook it calls again, which it
 * does for an instance Laravel applies no extender to (see
 * `WideningPhaseTest`). With no hook listed nothing is extended. Registering
 * builds none of the listed hooks, registering again wraps nothing twice, and
 * the bound hook keeps its lifetime, in a queue worker and in each Octane
 * sandbox.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ListedGrantHooks::class)]
#[CoversClass(SeamBindings::class)]
final class ListedGrantHooksTest extends TestCase
{
    /** @var \ArrayObject<int, string> The names of the hooks that ran, in order. */
    private \ArrayObject $ran;

    /**
     * Start with no hook run and no deferred binding.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->ran = new \ArrayObject;

        DeferredBindingProvider::$objects = [];
    }

    /**
     * Forget the deferred bindings.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        DeferredBindingProvider::$objects = [];

        parent::tearDown();
    }

    /**
     * Provide each way of binding the hook.
     *
     * @return iterable<string, array{string}>
     */
    public static function bindingProvider(): iterable
    {
        foreach (['bind', 'singleton', 'scoped', 'instance'] as $method) {
            yield $method => [$method];
        }
    }

    /**
     * The listed hooks run first, in the order listed, and the hook bound
     * before the package registered after them, however it was bound.
     *
     * @param  string  $method
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('bindingProvider')]
    public function testTheListedHooksRunBeforeAHookBoundEarlier(string $method): void
    {
        $app = $this->unboundHook();

        self::bind($app, $method, $this->hook('bound'));

        $this->registerTwoHooks();

        self::assertInstanceOf(ListedGrantHooks::class, $app->make(GrantHook::class));
        self::assertSame(['first', 'second', 'bound'], $this->widen($app));
    }

    /**
     * Provide each way of binding the hook that Laravel extends as it builds
     * the hook.
     *
     * @return iterable<string, array{string}>
     */
    public static function extendedBindingProvider(): iterable
    {
        foreach (['bind', 'singleton', 'scoped'] as $method) {
            yield $method => [$method];
        }
    }

    /**
     * A hook bound after the package registered no longer replaces the listed
     * hooks: they run before it, however it was bound but as an instance.
     *
     * @param  string  $method
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('extendedBindingProvider')]
    public function testTheListedHooksRunBeforeAHookBoundLater(string $method): void
    {
        $app = $this->unboundHook();

        self::bind($app, $method, $this->hook('earlier'));

        $this->registerTwoHooks();

        self::bind($app, $method, $this->hook('later'));

        self::assertSame(['first', 'second', 'later'], $this->widen($app));
    }

    /**
     * A hook already wrapped is returned as it is, so the grant service wraps
     * the hook it calls without wrapping a wrapped one again.
     *
     * @return void
     */
    public function testAWrappedHookIsNotWrappedAgain(): void
    {
        $app  = $this->unboundHook();
        $hook = ListedGrantHooks::wrap(new RecordingGrantHook, $app);

        self::assertSame($hook, ListedGrantHooks::wrap($hook, $app));
        self::assertSame($hook, ListedGrantHooks::around($hook, $app));
    }

    /**
     * An extender registered after the package decorates the wrapped hook, and
     * the grant service wraps the decoration again: the listed hooks run once,
     * first, then the decoration and the bound hook.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheListedHooksRunOnceAroundALaterDecoration(): void
    {
        $app = $this->unboundHook();
        $ran = $this->ran;

        $app->bind(GrantHook::class, fn (): GrantHook => $this->hook('bound'));

        $this->registerTwoHooks();

        $app->extend(GrantHook::class, static fn (GrantHook $hook): GrantHook => new SecondGrantHook(static function (GrantWidening $widening) use ($hook, $ran): void {
            $ran->append('decorated');
            $hook->beforeWidening($widening);
        }));

        ListedGrantHooks::wrap($app->make(GrantHook::class), $app)->beforeWidening(self::widening());

        self::assertSame(['first', 'second', 'decorated', 'bound'], $ran->getArrayCopy());
    }

    /**
     * The listed hooks run each time the wrapped hook is called, with the same
     * widening too, as when a call is tried again, and after a refusal.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheListedHooksRunForEachCall(): void
    {
        $app      = $this->unboundHook();
        $refusing = new RefusingGrantHook;
        $widening = self::widening();

        $app->instance(GrantHook::class, $refusing);

        $this->registerTwoHooks();

        $hook = $app->make(GrantHook::class);

        foreach ([1, 2] as $call) {
            try {
                $hook->beforeWidening($widening);

                self::fail("The widening was not refused on call {$call}.");
            } catch (GrantRefusedException) {
                self::assertSame($call, $refusing->refused);
            }
        }

        self::assertSame(['first', 'second', 'first', 'second'], $this->ran->getArrayCopy());
    }

    /**
     * Provide a refusing hook on either side of the bound hook.
     *
     * @return iterable<string, array{bool}>
     */
    public static function refusalProvider(): iterable
    {
        yield 'a listed hook refuses' => [true];
        yield 'the bound hook refuses' => [false];
    }

    /**
     * Either a listed hook or the bound hook may refuse the widening, so
     * nothing either would refuse is let through.
     *
     * @param  bool  $listedRefuses
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('refusalProvider')]
    public function testEitherHookMayRefuse(bool $listedRefuses): void
    {
        $recording = new RecordingGrantHook;
        $refusing  = new RefusingGrantHook;
        $app       = $this->unboundHook();

        $app->instance(GrantHook::class, $listedRefuses ? $recording : $refusing);
        $app->instance(RefusingGrantHook::class, $refusing);
        $app->instance(RecordingGrantHook::class, $recording);

        $this->register([$listedRefuses ? RefusingGrantHook::class : RecordingGrantHook::class]);

        try {
            $app->make(GrantHook::class)->beforeWidening(self::widening());

            self::fail('The widening was not refused.');
        } catch (GrantRefusedException) {
            self::assertSame(1, $refusing->refused);
        }

        self::assertCount($listedRefuses ? 0 : 1, $recording->widenings);
    }

    /**
     * With no hook listed nothing is extended: a hook bound before or after the
     * package registered stands alone.
     *
     * @return void
     */
    public function testWithNoHookListedTheBoundHookStandsAlone(): void
    {
        $earlier = new RecordingGrantHook;
        $later   = new RecordingGrantHook;
        $app     = $this->unboundHook();

        $app->bind(GrantHook::class, static fn (): GrantHook => $earlier);

        $this->register([]);

        self::assertSame($earlier, $app->make(GrantHook::class));

        $app->singleton(GrantHook::class, static fn (): GrantHook => $later);

        self::assertSame($later, $app->make(GrantHook::class));
    }

    /**
     * With the list missing nothing is extended, and the package's default
     * holds no hook.
     *
     * @return void
     */
    public function testWithTheListMissingTheDefaultHoldsNoHook(): void
    {
        $app = $this->unboundHook();

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(ConfigRepository::class);

        /** @var array<string, mixed> $authorization */
        $authorization = $config->get('authorization');

        unset($authorization['grant_hooks']);

        $config->set('authorization', $authorization);

        (new AuthorizationServiceProvider($app))->register();

        $default = $app->make(GrantHook::class);

        self::assertInstanceOf(GrantHooks::class, $default);
        self::assertTrue($default->isEmpty());
    }

    /**
     * With nothing bound, the listed hooks run before the package's default,
     * which holds none of them, so each runs once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWithNothingBoundTheListedHooksRunOnce(): void
    {
        $app = $this->unboundHook();

        $this->registerTwoHooks();

        self::assertInstanceOf(ListedGrantHooks::class, $app->make(GrantHook::class));
        self::assertSame(['first', 'second'], $this->widen($app));
    }

    /**
     * Provide whether the application learns of the deferred provider before
     * the package registers.
     *
     * @return iterable<string, array{bool}>
     */
    public static function deferredProvider(): iterable
    {
        yield 'learned of before' => [true];
        yield 'learned of after' => [false];
    }

    /**
     * A hook a deferred provider binds, whether the application learned of the
     * provider before the package registered or after, is wrapped when it is
     * first resolved, and the provider is not loaded before then.
     *
     * @param  bool  $before
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('deferredProvider')]
    public function testTheListedHooksRunBeforeAHookADeferredProviderBinds(bool $before): void
    {
        $app = $this->unboundHook();

        DeferredBindingProvider::$objects = [GrantHook::class => $this->hook('deferred')];

        if ($before) {
            $app->addDeferredServices([GrantHook::class => DeferredBindingProvider::class]);
        }

        $this->registerTwoHooks();

        $app->addDeferredServices([GrantHook::class => DeferredBindingProvider::class]);

        self::assertFalse($app->providerIsLoaded(DeferredBindingProvider::class));
        self::assertSame(['first', 'second', 'deferred'], $this->widen($app));
        self::assertTrue($app->providerIsLoaded(DeferredBindingProvider::class));
    }

    /**
     * An extender a sibling package registered on the contract before the
     * package registered decorates the bound hook, typed to its own class, and
     * the listed hooks run before the decorated hook; one registered after the
     * package receives the wrapped hook.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testExtendersApplyInTheOrderTheyWereRegistered(): void
    {
        $app = $this->unboundHook();
        $ran = $this->ran;

        $app->bind(GrantHook::class, fn (): RecordingGrantHook => $this->hook('bound'));
        $app->extend(GrantHook::class, static fn (RecordingGrantHook $hook): GrantHook => new SecondGrantHook(static function (GrantWidening $widening) use ($hook, $ran): void {
            $ran->append('decorated');
            $hook->beforeWidening($widening);
        }));

        $this->registerTwoHooks();

        /** @var \ArrayObject<int, object> $received */
        $received = new \ArrayObject;

        $app->extend(GrantHook::class, static function (GrantHook $hook) use ($received): GrantHook {
            $received->append($hook);

            return $hook;
        });

        self::assertSame(['first', 'second', 'decorated', 'bound'], $this->widen($app));
        self::assertCount(1, $received);
        self::assertInstanceOf(ListedGrantHooks::class, $received[0]);
    }

    /**
     * Provide each way of binding the hook, the scoped closure that names the
     * contract by its return type among them, with how many times the hook is
     * built across two resolutions in one job and one in the next.
     *
     * @return iterable<string, array{string, int}>
     */
    public static function lifetimeProvider(): iterable
    {
        yield 'bind' => ['bind', 3];
        yield 'singleton' => ['singleton', 1];
        yield 'scoped' => ['scoped', 2];
        yield 'scoped by its closure' => ['closure', 2];
    }

    /**
     * The bound hook keeps the lifetime it was bound with, and the wrapped hook
     * with it: the queue worker builds a scoped hook afresh for each job, a
     * scoped closure that names the contract by its return type included, and
     * keeps a singleton.
     *
     * @param  string  $method
     * @param  int  $builds
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('lifetimeProvider')]
    public function testTheBoundHookKeepsItsLifetime(string $method, int $builds): void
    {
        $app = $this->unboundHook();

        /** @var \ArrayObject<int, true> $built */
        $built   = new \ArrayObject;
        $factory = function () use ($built): GrantHook {
            $built->append(true);

            return $this->hook('bound');
        };

        if ($method === 'closure') {
            $app->scoped($factory);
        } else {
            self::bindBy($app, $method, $factory);
        }

        $this->registerTwoHooks();

        $first = $app->make(GrantHook::class);

        self::assertInstanceOf(ListedGrantHooks::class, $first);
        self::assertSame($method !== 'bind', $first === $app->make(GrantHook::class));

        $app->forgetScopedInstances();

        self::assertSame($method === 'singleton', $first === $app->make(GrantHook::class));
        self::assertCount($builds, $built);
        self::assertSame(['first', 'second', 'bound'], $this->widen($app));
    }

    /**
     * Each Octane sandbox cloned from the application wraps its own scoped
     * hook, and builds the listed hooks from itself, so nothing is resolved on
     * the application.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEachOctaneSandboxWrapsItsOwnHook(): void
    {
        $app = $this->unboundHook();
        $ran = $this->ran;

        /** @var \ArrayObject<int, true> $listed */
        $listed = new \ArrayObject;

        $app->scoped(GrantHook::class, fn (): GrantHook => $this->hook('bound'));
        $app->scoped(SecondGrantHook::class, static function () use ($listed, $ran): SecondGrantHook {
            $listed->append(true);

            return new SecondGrantHook(static fn () => $ran->append('listed'));
        });

        $this->register([SecondGrantHook::class]);

        $hooks = [];

        foreach (['first', 'second'] as $request) {
            $sandbox = clone $app;
            $hook    = $sandbox->make(GrantHook::class);

            self::assertInstanceOf(ListedGrantHooks::class, $hook, "The {$request} request's hook is not wrapped.");

            $hook->beforeWidening(self::widening());

            self::assertTrue($sandbox->resolved(SecondGrantHook::class), "The {$request} request did not build its listed hook.");

            $hooks[] = $hook;
        }

        self::assertNotSame($hooks[0], $hooks[1]);
        self::assertSame(['listed', 'bound', 'listed', 'bound'], $ran->getArrayCopy());
        self::assertCount(2, $listed);
        self::assertFalse($app->resolved(GrantHook::class));
        self::assertFalse($app->resolved(SecondGrantHook::class));
    }

    /**
     * Registering again in the same container wraps the bound hook once, so the
     * listed hooks run once, however the hook was bound.
     *
     * @param  string  $method
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('bindingProvider')]
    public function testRegisteringAgainWrapsTheHookOnce(string $method): void
    {
        $app = $this->unboundHook();

        self::bind($app, $method, $this->hook('bound'));

        $this->registerTwoHooks();
        $this->registerTwoHooks();

        self::assertSame(['first', 'second', 'bound'], $this->widen($app));
    }

    /**
     * Registering resolves neither the bound hook nor the listed hooks, however
     * the hook was bound, when nothing watches the contract for rebinding: an
     * instance is wrapped as it is held, and nothing is built.
     *
     * @param  string  $method
     * @return void
     */
    #[DataProvider('bindingProvider')]
    public function testRegisteringResolvesNothing(string $method): void
    {
        $app = $this->unboundHook();

        self::bind($app, $method, new RecordingGrantHook);

        /** @var \ArrayObject<int, string> $resolutions */
        $resolutions = new \ArrayObject;

        $app->beforeResolving(static function (string $abstract) use ($resolutions): void {
            if (\str_starts_with($abstract, 'config')) {
                return;
            }

            $resolutions->append($abstract);
        });

        $this->register([RecordingGrantHook::class]);

        self::assertSame([], $resolutions->getArrayCopy());
        self::assertSame($method === 'instance', $app->resolved(GrantHook::class), 'Only an instance is held, and wrapped as held.');
        self::assertFalse($app->resolved(RecordingGrantHook::class));
    }

    /**
     * A watcher of the contract is handed the wrapped hook when the package
     * registers, as Laravel rebinds a resolved contract it extends, and the
     * listed hooks are still not built.
     *
     * @return void
     */
    public function testARebindingWatcherIsHandedTheWrappedHook(): void
    {
        $app = $this->unboundHook();

        /** @var \ArrayObject<int, object> $handed */
        $handed = new \ArrayObject;

        /** @var \ArrayObject<int, true> $listed */
        $listed = new \ArrayObject;

        $app->singleton(GrantHook::class, RefusingGrantHook::class);
        $app->rebinding(GrantHook::class, static function (mixed $container, object $hook) use ($handed): void {
            $handed->append($hook);
        });
        $app->bind(RecordingGrantHook::class, static function () use ($listed): RecordingGrantHook {
            $listed->append(true);

            return new RecordingGrantHook;
        });

        $this->register([RecordingGrantHook::class]);

        self::assertCount(1, $handed);
        self::assertInstanceOf(ListedGrantHooks::class, $handed[0]);
        self::assertCount(0, $listed);
    }

    /**
     * The listed hooks are built at the wrapped hook's first use, once, and
     * kept with it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheListedHooksAreBuiltOnceAtFirstUse(): void
    {
        $app = $this->unboundHook();

        /** @var \ArrayObject<int, true> $built */
        $built = new \ArrayObject;

        $app->bind(RecordingGrantHook::class, static function () use ($built): RecordingGrantHook {
            $built->append(true);

            return new RecordingGrantHook;
        });

        $this->register([RecordingGrantHook::class]);

        $hook = $app->make(GrantHook::class);

        self::assertCount(0, $built);

        $hook->beforeWidening(self::widening());
        $hook->beforeWidening(self::widening());

        self::assertCount(1, $built);
    }

    /**
     * A binding that resolves to anything but a grant hook is left as it is,
     * for the grant service to refuse, never wrapped as though it were one.
     *
     * @return void
     */
    public function testABindingThatIsNoHookIsLeftAsItIs(): void
    {
        $app = $this->unboundHook();

        $app->bind(GrantHook::class, static fn (): \stdClass => new \stdClass);

        $this->register([RecordingGrantHook::class]);

        self::assertInstanceOf(\stdClass::class, $app[GrantHook::class]);
    }

    /**
     * Return the application with nothing bound on the grant hook contract and
     * no extender of it.
     *
     * @return \Illuminate\Foundation\Application
     */
    private function unboundHook(): Application
    {
        $app = $this->app;

        self::assertInstanceOf(Application::class, $app);

        $app->forgetExtenders(GrantHook::class);

        unset($app[GrantHook::class]);

        return $app;
    }

    /**
     * Return a hook that notes its name when it runs.
     *
     * @param  string  $name
     * @return \Tests\Fixtures\GrantHooks\RecordingGrantHook
     */
    private function hook(string $name): RecordingGrantHook
    {
        $ran = $this->ran;

        return new RecordingGrantHook(static fn () => $ran->append($name));
    }

    /**
     * Run the hook the contract resolves to with a widening, and return the
     * names of the hooks that ran, in order.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return list<string>
     *
     * @throws \Throwable
     */
    private function widen(Application $app): array
    {
        $this->ran->exchangeArray([]);

        $app->make(GrantHook::class)->beforeWidening(self::widening());

        return \array_values($this->ran->getArrayCopy());
    }

    /**
     * Bind the hook on the contract the way the method names.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @param  string  $method
     * @param  \SineMacula\Laravel\Authorization\Contracts\GrantHook  $hook
     * @return void
     */
    private static function bind(Application $app, string $method, GrantHook $hook): void
    {
        if ($method === 'instance') {
            $app->instance(GrantHook::class, $hook);

            return;
        }

        self::bindBy($app, $method, static fn (): GrantHook => $hook);
    }

    /**
     * Bind the factory on the contract with the method, `bind`, `singleton` or
     * `scoped`, it names.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @param  string  $method
     * @param  \Closure(): object  $factory
     * @return void
     */
    private static function bindBy(Application $app, string $method, \Closure $factory): void
    {
        $binders = [
            'bind'      => static fn () => $app->bind(GrantHook::class, $factory),
            'singleton' => static fn () => $app->singleton(GrantHook::class, $factory),
            'scoped'    => static fn () => $app->scoped(GrantHook::class, $factory),
        ];

        $binders[$method]();
    }

    /**
     * List two hooks, which note `first` and `second` when they run, and
     * register the package.
     *
     * @return void
     */
    private function registerTwoHooks(): void
    {
        $app = $this->app;
        $ran = $this->ran;

        self::assertInstanceOf(Application::class, $app);

        $app->instance(RecordingGrantHook::class, $this->hook('first'));
        $app->instance(SecondGrantHook::class, new SecondGrantHook(static fn () => $ran->append('second')));

        $this->register([RecordingGrantHook::class, SecondGrantHook::class]);
    }

    /**
     * List the hooks in the configuration and register the package.
     *
     * @param  list<class-string<\SineMacula\Laravel\Authorization\Contracts\GrantHook>>  $hooks
     * @return void
     */
    private function register(array $hooks): void
    {
        $app = $this->app;

        self::assertInstanceOf(Application::class, $app);

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(ConfigRepository::class);
        $config->set('authorization.grant_hooks', $hooks);

        (new AuthorizationServiceProvider($app))->register();
    }

    /**
     * Return a widening of no grants.
     *
     * @return \SineMacula\Laravel\Authorization\Hooks\GrantWidening
     */
    private static function widening(): GrantWidening
    {
        $identity = new Reference('identities', '1');

        return new GrantWidening('operation', true, null, null, null, $identity, $identity, [], new \DateTimeImmutable);
    }
}
