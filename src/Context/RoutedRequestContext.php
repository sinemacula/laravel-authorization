<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Context;

use Illuminate\Contracts\Container\Container;
use Illuminate\Http\Request;
use SineMacula\Laravel\Authorization\Contracts\RequestContext;
use SineMacula\Laravel\Authorization\Contracts\ScopeInvariant;

/**
 * The default request context: the container's current request, once routed
 * (AUTHZ-8.6).
 *
 * Supplies the client IP as Laravel resolves it behind the trusted proxies
 * (`ip`), the method (`method`) and the route's name (`route`). A request that
 * has not been routed, such as the one a console command or a queued job holds,
 * supplies nothing, so the namespace is absent and every `request` key is
 * missing; so is a key the request does not carry, such as the name of an
 * unnamed route. Nothing is ever read from what the caller passes.
 *
 * The request is read from the container on every check, never kept, so a
 * long-lived worker reads the request it is serving.
 *
 * It is marked `ScopeInvariant`: it reads the request alone, never the record a
 * check is about, so `whereAuthorized()` reads it once for a query.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RoutedRequestContext implements RequestContext, ScopeInvariant
{
    /**
     * Create a new routed request context.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Container the current request is read from. */
        private Container $container,
    ) {}

    /**
     * Return the routed request's client IP, method and route name.
     *
     * @return array<string, mixed>
     */
    #[\Override]
    public function values(): array
    {
        $request = $this->container->bound('request') ? $this->container->make('request') : null;
        $route   = $request instanceof Request ? $request->route() : null;

        if (!$request instanceof Request || $route === null) {
            return [];
        }

        return \array_filter([
            'ip'     => $request->ip(),
            'method' => $request->getMethod(),
            'route'  => $route->getName(),
        ], static fn (?string $value): bool => $value !== null);
    }
}
