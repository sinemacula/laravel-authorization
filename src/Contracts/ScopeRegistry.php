<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Contracts;

/**
 * Scope registry contract (AUTHZ-13.5).
 *
 * Answers which scopes a credential may carry, so the scopes issued to a
 * credential name real permissions. The package ships a registry backed by the
 * permission catalogue and the scope map (`CatalogueScopeRegistry`) but binds
 * none: an application, or `sinemacula/laravel-iam` for
 * `laravel-authentication`'s scope registry (AUTH-4.5), binds it where scopes
 * are issued.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface ScopeRegistry
{
    /**
     * Determine whether a credential may carry the scope.
     *
     * @param  string  $scope
     * @return bool
     */
    public function isValid(string $scope): bool;

    /**
     * Return every scope a credential may carry by name.
     *
     * @return list<string>
     */
    public function scopes(): array;
}
