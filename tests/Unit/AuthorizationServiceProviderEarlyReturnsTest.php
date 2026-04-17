<?php

declare(strict_types = 1);

namespace Tests\Unit;

use Illuminate\Container\Container;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Facades\Facade;
use Mockery;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Registrars\BladeDirectiveRegistrar;
use SineMacula\Laravel\Authorization\Registrars\EventListenerRegistrar;
use SineMacula\Laravel\Authorization\Registrars\GateRegistrar;

/**
 * Unit coverage for the service provider's defensive early-return
 * branches.
 *
 * Each of the boot-time wiring methods
 * (`registerCacheInvalidationListeners`, `registerOctaneResetListener`,
 * `registerRouteMiddleware`, `registerBladeDirectives`,
 * `offerPublishing`) short-circuits when its required container
 * binding is absent. These branches matter for library-mode
 * embedding — non-Laravel applications that load the package for
 * its core evaluator without wanting the full framework glue.
 *
 * The tests exercise each branch against a bare `Container` that
 * never binds `events`, `router`, `blade.compiler`, or the Octane
 * request class, and an application whose `runningInConsole()`
 * returns false.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(AuthorizationServiceProvider::class)]
#[CoversClass(GateRegistrar::class)]
#[CoversClass(BladeDirectiveRegistrar::class)]
#[CoversClass(EventListenerRegistrar::class)]
final class AuthorizationServiceProviderEarlyReturnsTest extends TestCase
{
    /**
     * Swap the facade root after each test to avoid leaking Mockery
     * doubles into other suites.
     *
     * @return void
     */
    protected function tearDown(): void
    {
        Facade::clearResolvedInstances();
        Facade::setFacadeApplication(null);
        \Mockery::close();

        parent::tearDown();
    }

    /**
     * When the container has no `Dispatcher` binding the cache
     * invalidation wiring short-circuits without raising.
     *
     * @return void
     */
    public function testCacheInvalidationListenersSkipWhenDispatcherUnbound(): void
    {
        $app = $this->bareApplication();

        $this->invokePrivateOn(new EventListenerRegistrar($app), 'registerCacheInvalidationListeners');

        self::assertFalse($app->bound(\Illuminate\Contracts\Events\Dispatcher::class));
    }

    /**
     * The Octane reset listener registration short-circuits when the
     * container has no `Dispatcher` binding — covers the second half
     * of the `!class_exists(...) || !bound(Dispatcher)` guard.
     *
     * @return void
     */
    public function testOctaneResetListenerSkipsWhenDispatcherUnbound(): void
    {
        $app = $this->bareApplication();

        // No exception and no listener wiring attempt.
        $this->invokePrivateOn(new EventListenerRegistrar($app), 'registerOctaneResetListener');

        self::assertFalse($app->bound(\Illuminate\Contracts\Events\Dispatcher::class));
    }

    /**
     * Route middleware registration short-circuits when the
     * container has no `router` binding.
     *
     * @return void
     */
    public function testRouteMiddlewareSkipsWhenRouterUnbound(): void
    {
        $app      = $this->bareApplication();
        $provider = new AuthorizationServiceProvider($app);

        $this->invokeProtected($provider, 'registerRouteMiddleware');

        self::assertFalse($app->bound('router'));
    }

    /**
     * Blade directive registration short-circuits when the
     * container has no `blade.compiler` binding.
     *
     * @return void
     */
    public function testBladeDirectivesSkipWhenCompilerUnbound(): void
    {
        $app = $this->bareApplication();

        (new BladeDirectiveRegistrar($app))->register();

        self::assertFalse($app->bound('blade.compiler'));
    }

    /**
     * Asset publishing short-circuits when the application is not
     * running in the console.
     *
     * @return void
     */
    public function testOfferPublishingSkipsWhenNotInConsole(): void
    {
        $app = \Mockery::mock(Application::class);
        $app->shouldReceive('runningInConsole')->once()->andReturnFalse();

        Facade::setFacadeApplication($app);

        $provider = new AuthorizationServiceProvider($app);

        $this->invokeProtected($provider, 'offerPublishing');

        self::assertTrue(true);
    }

    /**
     * Build a minimal `Application` double whose `bound()` mirrors a
     * bare `Container` so the provider's container probes behave
     * exactly as they would under non-Laravel embedding.
     *
     * @return \Illuminate\Contracts\Foundation\Application
     */
    private function bareApplication(): Application
    {
        $container = new Container;

        /** @var \Illuminate\Contracts\Foundation\Application $app */
        $app = \Mockery::mock(Application::class);
        $app->shouldReceive('bound')->andReturnUsing(static fn (string $abstract): bool => $container->bound($abstract));
        $app->shouldReceive('runningInConsole')->andReturnFalse();
        $app->shouldReceive('make')->andReturnUsing(static fn (string $abstract): mixed => $container->make($abstract));

        return $app;
    }

    /**
     * Invoke a protected method on the service provider via
     * reflection so the early-return branches can be exercised
     * without booting the full framework.
     *
     * @param  \SineMacula\Laravel\Authorization\AuthorizationServiceProvider  $provider
     * @param  string  $method
     * @return void
     */
    private function invokeProtected(AuthorizationServiceProvider $provider, string $method): void
    {
        $reflection = new \ReflectionMethod($provider, $method);
        $reflection->invoke($provider);
    }

    /**
     * Invoke a private method on an arbitrary target via reflection.
     *
     * @param  object  $target
     * @param  string  $method
     * @return void
     */
    private function invokePrivateOn(object $target, string $method): void
    {
        $reflection = new \ReflectionMethod($target, $method);
        $reflection->invoke($target);
    }
}
