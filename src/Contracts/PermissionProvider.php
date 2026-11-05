<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Contracts;

/**
 * Contract for modular permission registration.
 *
 * Packages and modules that ship their own permission sets implement this
 * contract and register their class in the `authorization.permission_providers`
 * config array. The service provider validates the configured classes at boot
 * but never reads a provider there, so booting writes no `Permission` rows.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface PermissionProvider
{
    /**
     * Return the permission strings this provider contributes.
     *
     * @return array<int, string>
     */
    public function permissions(): array;

    /**
     * Return the guard name these permissions are scoped to.
     *
     * Return null for guard-agnostic permissions.
     *
     * @return string|null
     */
    public function guard(): ?string;
}
