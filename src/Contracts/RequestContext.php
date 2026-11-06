<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Contracts;

/**
 * Request context contract (AUTHZ-8.6).
 *
 * Supplies the `request` namespace of the context. It is trusted: its values
 * come from the request the application received, never from what the caller
 * passes, and only rebinding this contract replaces it.
 *
 * The shipped default supplies Laravel's trusted-proxy-resolved client IP, the
 * method and the route name of a routed request, and nothing otherwise.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface RequestContext
{
    /**
     * Return the namespace's values for the current check, nested by key. A key
     * left out is missing; an empty array leaves the namespace absent.
     *
     * @return array<string, mixed>
     */
    public function values(): array;
}
