<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Console;

use SineMacula\Laravel\Authorization\Contracts\AuthorizableIdentity;

/**
 * Revoke a role from an authorizable identity.
 *
 * Accepts the identity as `{morphType}:{key}` (e.g. `user:123`)
 * and the role by name. Resolves the morph alias via the Eloquent
 * morph map, validates the `AuthorizableIdentity` contract, and
 * delegates to `revokeRole()`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class RevokeRoleCommand extends AbstractRoleAssignmentCommand
{
    /** @var string The console command signature. */
    protected $signature = 'authorization:revoke {identity : Identity in morphType:key format (e.g. user:123)} {role : Role name to revoke}';

    /** @var string The console command description. */
    protected $description = 'Revoke a role from an authorizable identity';

    /**
     * Revoke the role from the resolved identity.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\AuthorizableIdentity  $model
     * @param  string  $roleName
     * @return void
     */
    #[\Override]
    protected function mutate(AuthorizableIdentity $model, string $roleName): void
    {
        $model->revokeRole($roleName);
    }

    /**
     * Build the revoke success message.
     *
     * @param  string  $roleName
     * @param  string  $identityArg
     * @return string
     */
    #[\Override]
    protected function successMessage(string $roleName, string $identityArg): string
    {
        return "Role '{$roleName}' revoked from {$identityArg}.";
    }
}
