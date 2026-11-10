<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Support;

use Illuminate\Container\Container;
use Illuminate\Http\Request;

/**
 * The client of the request an operation is begun in: the IP address, as
 * Laravel resolves it behind the trusted proxies, and the user agent, read from
 * the container's current request once it is routed, as the request context
 * reads it (see `Context\RoutedRequestContext`).
 *
 * A request that has not been routed, such as the one a console command or a
 * queued job holds, has no client, so neither is read. The request is read when
 * asked, never kept, so a long-lived worker reads the request it is serving. It
 * is the helper that turns the request into plain values for the core (D22):
 * `Operation::begin()` asks it, and nothing else reads the request for an
 * operation.
 *
 * Both values are personal data: they are carried to the grant hook alone (see
 * `Operation`).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RequestClient
{
    /**
     * Return the IP address and the user agent of the routed request the
     * container holds, each null when the request does not carry it, or two
     * nulls when there is no routed request.
     *
     * @return array{0: string|null, 1: string|null}
     */
    public static function current(): array
    {
        $container = Container::getInstance();
        $request   = $container->bound('request') ? $container->make('request') : null;

        if (!$request instanceof Request || $request->route() === null) {
            return [null, null];
        }

        return [$request->ip(), $request->userAgent()];
    }
}
