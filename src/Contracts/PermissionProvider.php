<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Contracts;

/**
 * Contract for modular permission registration.
 *
 * Packages and modules that ship their own permission sets implement this
 * contract and register their class in the `authorization.permission_providers`
 * config array. `authorization:sync` resolves each provider through the
 * container and writes the definitions it returns to the permission catalogue,
 * alongside the cases of the configured permission enums. The service provider
 * validates the configured classes at boot, and reads a provider there only to
 * check the scope map when `authorization.session.scopes` names a scope;
 * booting never writes `Permission` rows either way.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface PermissionProvider
{
    /**
     * Return the permissions this provider declares, each with its name,
     * description, category and guard (null for guard-agnostic).
     *
     * @return list<\SineMacula\Laravel\Authorization\Support\PermissionDefinition>
     */
    public function permissions(): array;
}
