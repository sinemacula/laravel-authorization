<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Contracts;

/**
 * Principal resolver contract.
 *
 * Bridges the authorization engine to whatever concept of "the current
 * principal" the host application uses. The default binding returns null so the
 * package is anonymous-safe and carries no hard runtime dependency on any
 * authentication layer. Host applications or ecosystem umbrella packages bind
 * their own implementation when they want authorization checks to consult an
 * authenticated subject.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface PrincipalResolver
{
    /**
     * Resolve the current principal.
     *
     * Implementations return a plain object that describes the acting subject
     * or null when the request is anonymous. The engine does not type-hint any
     * specific principal shape: capability is detected via the authorizable
     * contract.
     *
     * @return object|null
     */
    public function resolve(): ?object;
}
