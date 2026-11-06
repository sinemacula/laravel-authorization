<?php

declare(strict_types = 1);

namespace Tests\Feature\Context;

use Illuminate\Container\Container;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Routing\Route;
use Illuminate\Support\Facades\Route as Router;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Context\RoutedRequestContext;
use SineMacula\Laravel\Authorization\Contracts\RequestContext;
use SineMacula\Laravel\Authorization\Contracts\ScopeInvariant;
use Tests\TestCase;

/**
 * Feature coverage for `RoutedRequestContext`, the default request context,
 * which supplies the routed request's client IP, method and route name.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(RoutedRequestContext::class)]
final class RoutedRequestContextTest extends TestCase
{
    /**
     * Restore the trusted proxies after every test.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Request::setTrustedProxies([], Request::HEADER_X_FORWARDED_FOR);

        parent::tearDown();
    }

    /**
     * A routed request supplies its client IP, method and route name.
     *
     * @return void
     */
    public function testARoutedRequestSuppliesItsIpMethodAndRoute(): void
    {
        $this->routeReporting('/posts', 'posts.index');

        $this->withServerVariables(['REMOTE_ADDR' => '10.0.0.5'])
            ->post('/posts')
            ->assertExactJson(['ip' => '10.0.0.5', 'method' => 'POST', 'route' => 'posts.index']);
    }

    /**
     * The client IP is the one Laravel resolves: a forwarded address counts
     * only when the request came through a trusted proxy.
     *
     * @return void
     */
    public function testTheIpIsResolvedBehindTheTrustedProxies(): void
    {
        $context = $this->context();
        $request = self::routed('/posts', 'GET', '10.0.0.5', 'posts.index');

        $request->headers->set('X-Forwarded-For', '192.0.2.7');
        $this->app()->instance('request', $request);

        self::assertSame(['ip' => '10.0.0.5', 'method' => 'GET', 'route' => 'posts.index'], $context->values());

        Request::setTrustedProxies(['10.0.0.5'], Request::HEADER_X_FORWARDED_FOR);

        self::assertSame(['ip' => '192.0.2.7', 'method' => 'GET', 'route' => 'posts.index'], $context->values());
    }

    /**
     * An unnamed route supplies no route name, so the key is missing.
     *
     * @return void
     */
    public function testAnUnnamedRouteSuppliesNoRouteName(): void
    {
        $this->routeReporting('/drafts', null);

        $this->withServerVariables(['REMOTE_ADDR' => '10.0.0.5'])
            ->post('/drafts')
            ->assertExactJson(['ip' => '10.0.0.5', 'method' => 'POST']);
    }

    /**
     * A request that has not been routed, such as a console command's, supplies
     * nothing.
     *
     * @return void
     */
    public function testARequestNotRoutedSuppliesNothing(): void
    {
        $context = $this->context();

        self::assertInstanceOf(RequestContext::class, $context);
        self::assertSame([], $context->values());

        $this->app()->instance('request', Request::create('/posts', 'GET', server: ['REMOTE_ADDR' => '10.0.0.1']));

        self::assertSame([], $context->values());
    }

    /**
     * The request is read from the container on every check, so the context
     * reads the request it is serving now.
     *
     * @return void
     */
    public function testReadsTheContainersCurrentRequest(): void
    {
        $context = $this->context();

        $this->app()->instance('request', self::routed('/a', 'GET', '10.0.0.1', 'a'));
        self::assertSame(['ip' => '10.0.0.1', 'method' => 'GET', 'route' => 'a'], $context->values());

        $this->app()->instance('request', self::routed('/b', 'PUT', '10.0.0.2', 'b'));
        self::assertSame(['ip' => '10.0.0.2', 'method' => 'PUT', 'route' => 'b'], $context->values());
    }

    /**
     * A container holding no request, or something else as the request,
     * supplies nothing.
     *
     * @return void
     */
    public function testAContainerWithoutARequestSuppliesNothing(): void
    {
        $container = new Container;

        self::assertSame([], (new RoutedRequestContext($container))->values());

        $container->instance('request', new \stdClass);

        self::assertSame([], (new RoutedRequestContext($container))->values());
    }

    /**
     * It reads the request alone, so it is marked `ScopeInvariant` and a query
     * scope reads it once for a query.
     *
     * @return void
     */
    public function testItIsMarkedScopeInvariant(): void
    {
        self::assertContains(ScopeInvariant::class, \class_implements(RoutedRequestContext::class));
    }

    /**
     * Return the application.
     *
     * @return \Illuminate\Foundation\Application
     */
    private function app(): Application
    {
        $app = $this->app;

        self::assertNotNull($app);

        return $app;
    }

    /**
     * Resolve the request context from the container.
     *
     * @return \SineMacula\Laravel\Authorization\Context\RoutedRequestContext
     */
    private function context(): RoutedRequestContext
    {
        return $this->app()->make(RoutedRequestContext::class);
    }

    /**
     * Register a route that reports the request context's values.
     *
     * @param  string  $uri
     * @param  string|null  $name
     * @return void
     */
    private function routeReporting(string $uri, ?string $name): void
    {
        $route = Router::post($uri, static fn (RoutedRequestContext $context): array => $context->values());

        if ($name === null) {
            return;
        }

        $route->name($name);
    }

    /**
     * Build a request routed to a named route.
     *
     * @param  string  $uri
     * @param  string  $method
     * @param  string  $ip
     * @param  string  $name
     * @return \Illuminate\Http\Request
     */
    private static function routed(string $uri, string $method, string $ip, string $name): Request
    {
        $request = Request::create($uri, $method, server: ['REMOTE_ADDR' => $ip]);
        $route   = (new Route([$method], $uri, static fn (): string => 'ok'))->name($name);

        $request->setRouteResolver(static fn (): Route => $route);

        return $request;
    }
}
