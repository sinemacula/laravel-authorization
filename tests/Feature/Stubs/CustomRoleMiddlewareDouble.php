<?php

declare(strict_types = 1);

namespace Tests\Feature\Stubs;

use Illuminate\Http\Request;

/**
 * Stand-in middleware used by `RouteMiddlewareTest` to verify the
 * service provider keeps hands off an alias a consumer has already
 * wired to their own class.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
final class CustomRoleMiddlewareDouble
{
    /**
     * Stub invoke — never actually executed in these tests.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure(\Illuminate\Http\Request): mixed  $next
     * @return mixed
     */
    public function handle(Request $request, \Closure $next): mixed
    {
        return $next($request);
    }
}
