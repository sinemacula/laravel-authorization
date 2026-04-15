<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Permissions\Traits;

/**
 * Authorizable trait.
 *
 * Provides a default implementation of the Authorizable contract.
 * The consuming application overrides these methods with its own
 * logic, such as querying a roles or permissions table.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
trait Authorizable // @phpstan-ignore trait.unused
{
    /**
     * Determine if the principal has the given permission.
     *
     * @param  string  $permission
     * @return bool
     */
    public function hasPermission(string $permission): bool
    {
        return in_array($permission, $this->getPermissions(), true);
    }

    /**
     * Determine if the principal has the given role.
     *
     * @param  string  $role
     * @return bool
     */
    public function hasRole(string $role): bool
    {
        return in_array($role, $this->getRoles(), true);
    }

    /**
     * Get all permissions assigned to the principal.
     *
     * Override this method to load permissions from a database or
     * other source.
     *
     * @return array<int, string>
     */
    public function getPermissions(): array
    {
        return [];
    }

    /**
     * Get all roles assigned to the principal.
     *
     * Override this method to load roles from a database or other
     * source.
     *
     * @return array<int, string>
     */
    public function getRoles(): array
    {
        return [];
    }

    /**
     * Get all policies attached to the principal.
     *
     * Override this method to load policies from a database or
     * other source.
     *
     * @return array<int, \SineMacula\Laravel\Iam\Permissions\Evaluation\Policy>
     */
    public function getPolicies(): array
    {
        return [];
    }
}
