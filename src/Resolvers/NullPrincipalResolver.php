<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Resolvers;

use SineMacula\Laravel\Authorization\Contracts\PrincipalResolver;

/**
 * Anonymous-safe default principal resolver.
 *
 * Always returns null, which makes the authorization engine deny every check
 * that reaches it. Applications wire their own resolver — typically one backed
 * by an authentication package or framework guard — through the
 * `authorization.principal_resolver` config entry or by binding the resolver
 * contract directly.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class NullPrincipalResolver implements PrincipalResolver
{
    /**
     * Always resolve to an anonymous principal.
     *
     * @return object|null
     */
    #[\Override]
    public function resolve(): ?object
    {
        return null;
    }
}
