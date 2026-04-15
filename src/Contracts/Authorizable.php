<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Iam\Permissions\Contracts;

/**
 * Authorizable contract.
 *
 * Implemented by principals that support role-based access control.
 * Provides methods for checking permissions, roles, and retrieving
 * the policies attached to the principal.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
interface Authorizable
{
    /**
     * Determine if the principal has the given permission.
     *
     * @param  string  $permission
     * @return bool
     */
    public function hasPermission(string $permission): bool;

    /**
     * Determine if the principal has the given role.
     *
     * @param  string  $role
     * @return bool
     */
    public function hasRole(string $role): bool;

    /**
     * Get all permissions assigned to the principal.
     *
     * @return array<int, string>
     */
    public function getPermissions(): array;

    /**
     * Get all roles assigned to the principal.
     *
     * @return array<int, string>
     */
    public function getRoles(): array;

    /**
     * Get all policies attached to the principal.
     *
     * @return array<int, \SineMacula\Laravel\Iam\Permissions\Evaluation\Policy>
     */
    public function getPolicies(): array;
}
