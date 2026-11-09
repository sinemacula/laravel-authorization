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
use SineMacula\Laravel\Authorization\Support\EarlierBinding;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Fixtures\GrantHooks\RecordingGrantHook;
use Tests\Fixtures\GrantHooks\RefusingGrantHook;
use Tests\TestCase;

/**
 * Feature tests for the grant hook a sibling package or the application bound
 * before the package registered, composed with the hooks the configuration
 * lists (N107).
 *
 * The listed hooks run first and the earlier binding after them, and any of
 * them may refuse. With no hook listed the earlier binding stands alone, with
 * nothing bound earlier the listed hooks run alone, and a binding made after
 * the package registered replaces the composite. Registering resolves nothing,
 * and the earlier binding keeps the lifetime it was bound with, in a queue
 * worker and in each Octane sandbox.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthorizationServiceProvider::class)]
#[CoversClass(GrantHooks::class)]
#[CoversClass(EarlierBinding::class)]
final class ComposedGrantHooksTest extends TestCase
{
    /** @var string The package-owned key that holds the earlier binding. */
    private const string EARLIER = 'authorization.earlier:' . GrantHook::class;

    /**
     * Provide each way of binding the earlier hook.
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
     * The listed hooks run first and the hook bound before the package
     * registered after them, however it was bound.
     *
     * @param  string  $method
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('bindingProvider')]
    public function testTheListedHooksRunBeforeTheEarlierBinding(string $method): void
    {
        /** @var \ArrayObject<int, string> $order */
        $order   = new \ArrayObject;
        $listed  = new RecordingGrantHook(static fn () => $order->append('listed'));
        $earlier = new RecordingGrantHook(static fn () => $order->append('earlier'));
        $app     = $this->bindEarlier($method, $earlier);

        $app->instance(RecordingGrantHook::class, $listed);

        $this->register([RecordingGrantHook::class]);

        $hook = $app->make(GrantHook::class);

        self::assertInstanceOf(GrantHooks::class, $hook);
        self::assertSame([$listed, $earlier], $hook->hooks());

        $hook->beforeWidening(self::widening());

        self::assertSame(['listed', 'earlier'], $order->getArrayCopy());
    }

    /**
     * Provide a refusing hook on either side of the composite.
     *
     * @return iterable<string, array{bool}>
     */
    public static function refusalProvider(): iterable
    {
        yield 'a listed hook refuses' => [true];
        yield 'the earlier binding refuses' => [false];
    }

    /**
     * Either a listed hook or the hook bound before the package registered may
     * refuse the widening, so nothing either would refuse is let through.
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
        $app       = $this->bindEarlier('instance', $listedRefuses ? $recording : $refusing);

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
     * With no hook listed, or the list missing, the hook bound before the
     * package registered stands alone.
     *
     * @return void
     */
    public function testWithNoHookListedTheEarlierBindingStands(): void
    {
        $earlier = new RecordingGrantHook;
        $app     = $this->bindEarlier('instance', $earlier);

        $this->register([]);

        self::assertSame($earlier, $app->make(GrantHook::class));
        self::assertFalse($app->bound(self::EARLIER));

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(ConfigRepository::class);

        /** @var array<string, mixed> $authorization */
        $authorization = $config->get('authorization');

        unset($authorization['grant_hooks']);

        $config->set('authorization', $authorization);

        (new AuthorizationServiceProvider($app))->register();

        self::assertSame($earlier, $app->make(GrantHook::class));
        self::assertFalse($app->bound(self::EARLIER));
    }

    /**
     * With nothing bound before the package registered, the listed hooks run
     * alone.
     *
     * @return void
     */
    public function testWithNothingBoundEarlierTheListedHooksRunAlone(): void
    {
        $listed = new RecordingGrantHook;
        $app    = $this->unboundHook();

        $app->instance(RecordingGrantHook::class, $listed);

        $this->register([RecordingGrantHook::class]);

        $hook = $app->make(GrantHook::class);

        self::assertInstanceOf(GrantHooks::class, $hook);
        self::assertSame([$listed], $hook->hooks());
        self::assertFalse($app->bound(self::EARLIER));
    }

    /**
     * A hook bound after the package registered replaces the composite, however
     * it was bound.
     *
     * @param  string  $method
     * @return void
     */
    #[DataProvider('bindingProvider')]
    public function testABindingMadeAfterRegistrationReplacesTheComposite(string $method): void
    {
        $later = new RecordingGrantHook;
        $app   = $this->bindEarlier('instance', new RecordingGrantHook);

        $this->register([RefusingGrantHook::class]);

        self::bind($app, $method, $later);

        self::assertSame($later, $app->make(GrantHook::class));
    }

    /**
     * Registering resolves neither the earlier binding nor the listed hooks nor
     * the composite, however the earlier hook was bound: it reads the
     * configuration and nothing else.
     *
     * @param  string  $method
     * @return void
     */
    #[DataProvider('bindingProvider')]
    public function testRegisteringResolvesNothing(string $method): void
    {
        $app = $this->bindEarlier($method, new RecordingGrantHook);

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
        self::assertFalse($app->resolved(GrantHook::class));
        self::assertSame($method === 'instance', $app->resolved(self::EARLIER), 'Only an instance is held as it was bound.');
    }

    /**
     * Provide each way of binding the earlier hook, and whether the queue
     * worker keeps it from one job to the next.
     *
     * @return iterable<string, array{string, bool}>
     */
    public static function lifetimeProvider(): iterable
    {
        yield 'bind' => ['bind', false];
        yield 'singleton' => ['singleton', true];
        yield 'scoped' => ['scoped', false];
    }

    /**
     * The earlier binding keeps the lifetime it was bound with: the composite
     * is built afresh for each job, and holds the same earlier hook only when
     * it was bound as a singleton.
     *
     * @param  string  $method
     * @param  bool  $kept
     * @return void
     */
    #[DataProvider('lifetimeProvider')]
    public function testTheEarlierBindingKeepsItsLifetime(string $method, bool $kept): void
    {
        $app = $this->unboundHook();

        self::bindBy($app, $method, static fn (): GrantHook => new RecordingGrantHook);

        $this->register([RefusingGrantHook::class]);

        $first = $app->make(GrantHook::class);

        self::assertSame($first, $app->make(GrantHook::class));

        $app->forgetScopedInstances();

        $second = $app->make(GrantHook::class);

        self::assertInstanceOf(GrantHooks::class, $first);
        self::assertInstanceOf(GrantHooks::class, $second);
        self::assertNotSame($first, $second);
        self::assertSame($kept, $first->hooks()[1] === $second->hooks()[1]);
    }

    /**
     * A singleton resolved before the package registered is composed as the
     * instance already resolved.
     *
     * @return void
     */
    public function testAnInstanceResolvedBeforeRegistrationIsKept(): void
    {
        $app = $this->unboundHook();

        $app->singleton(GrantHook::class, static fn (): GrantHook => new RecordingGrantHook);

        $earlier = $app->make(GrantHook::class);

        $this->register([RefusingGrantHook::class]);

        $hook = $app->make(GrantHook::class);

        self::assertInstanceOf(GrantHooks::class, $hook);
        self::assertSame($earlier, $hook->hooks()[1]);
    }

    /**
     * A contract aliased to a hook before the package registered composes the
     * hook the alias names.
     *
     * @return void
     */
    public function testAnAliasedHookIsComposed(): void
    {
        $earlier = new RecordingGrantHook;
        $app     = $this->unboundHook();

        $app->instance(RecordingGrantHook::class, $earlier);
        $app->alias(RecordingGrantHook::class, GrantHook::class);

        $this->register([RefusingGrantHook::class]);

        $hook = $app->make(GrantHook::class);

        self::assertInstanceOf(GrantHooks::class, $hook);
        self::assertSame($earlier, $hook->hooks()[1]);
    }

    /**
     * Each Octane sandbox cloned from the application builds its own composite,
     * holding the listed hooks and its own scoped earlier hook, and nothing is
     * resolved on the application itself.
     *
     * @return void
     */
    public function testEachOctaneSandboxComposesItsOwnHooks(): void
    {
        $listed = new RecordingGrantHook;
        $app    = $this->unboundHook();

        $app->scoped(GrantHook::class, static fn (): GrantHook => new RecordingGrantHook);
        $app->instance(RefusingGrantHook::class, new RefusingGrantHook);
        $app->instance(RecordingGrantHook::class, $listed);

        $this->register([RecordingGrantHook::class]);

        $hooks = [];

        foreach (['first', 'second'] as $request) {
            $hook = (clone $app)->make(GrantHook::class);

            self::assertInstanceOf(GrantHooks::class, $hook, "The {$request} request's hook is not the composite.");
            self::assertCount(2, $hook->hooks());
            self::assertSame($listed, $hook->hooks()[0]);
            self::assertInstanceOf(RecordingGrantHook::class, $hook->hooks()[1]);
            self::assertNotSame($listed, $hook->hooks()[1]);

            $hooks[] = $hook;
        }

        self::assertNotSame($hooks[0]->hooks()[1], $hooks[1]->hooks()[1]);
        self::assertFalse($app->resolved(GrantHook::class));
        self::assertFalse($app->resolved(self::EARLIER));
    }

    /**
     * Registering again in the same container does not take the package's own
     * binding for an earlier one, so the composite never holds itself.
     *
     * @return void
     */
    public function testRegisteringAgainDoesNotComposeThePackagesOwnBinding(): void
    {
        $listed  = new RecordingGrantHook;
        $earlier = new RefusingGrantHook;
        $app     = $this->bindEarlier('instance', $earlier);

        $app->instance(RecordingGrantHook::class, $listed);

        $this->register([RecordingGrantHook::class]);
        $this->register([RecordingGrantHook::class]);

        $hook = $app->make(GrantHook::class);

        self::assertInstanceOf(GrantHooks::class, $hook);
        self::assertSame([$listed, $earlier], $hook->hooks());
    }

    /**
     * An earlier binding that does not resolve to a grant hook is refused when
     * the composite is built, never taken as no hook.
     *
     * @return void
     */
    public function testAnEarlierBindingThatIsNoHookIsRefused(): void
    {
        $app = $this->unboundHook();

        $app->bind(GrantHook::class, static fn (): \stdClass => new \stdClass);
        $app->instance(RecordingGrantHook::class, new RecordingGrantHook);

        $this->register([RecordingGrantHook::class]);

        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('resolves to stdClass, which does not implement it.');

        $app->make(GrantHook::class);
    }

    /**
     * Return the application with nothing bound on the grant hook contract or
     * under the key of the earlier binding.
     *
     * @return \Illuminate\Foundation\Application
     */
    private function unboundHook(): Application
    {
        $app = $this->app;

        self::assertInstanceOf(Application::class, $app);

        $app->forgetExtenders(GrantHook::class);

        unset($app[GrantHook::class], $app[self::EARLIER]);

        return $app;
    }

    /**
     * Return the application with the hook bound on the contract the way the
     * method names, as a sibling package would before the package registers.
     *
     * @param  string  $method
     * @param  \SineMacula\Laravel\Authorization\Contracts\GrantHook  $hook
     * @return \Illuminate\Foundation\Application
     */
    private function bindEarlier(string $method, GrantHook $hook): Application
    {
        $app = $this->unboundHook();

        self::bind($app, $method, $hook);

        return $app;
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
