<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Console;

use Illuminate\Console\Command;
use SineMacula\Laravel\Authorization\Console\Concerns\ResolvesIdentity;
use SineMacula\Laravel\Authorization\Services\GrantService;

/**
 * Revoke a role from an authorizable identity.
 *
 * Accepts the identity as `{morphType}:{key}` (e.g. `user:123`) and the role by
 * name. Resolves the morph alias via the Eloquent morph map, validates the
 * `AuthorizableIdentity` contract, and revokes the role through the grant
 * service. A role the identity does not hold is reported as not held.
 *
 * The role name is revoked from the roles the identity holds within the tenant
 * scope, like any other query: every held role of that name is revoked, the
 * platform-wide one and, when the application's subject resolver resolves a
 * tenant in the console, the tenant's own. Without a tenant, only platform-wide
 * roles can be revoked.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class RevokeRoleCommand extends Command
{
    use ResolvesIdentity;

    /** @var string The console command signature. */
    protected $signature = <<<'EOD'
        authorization:revoke
                                    {identity : Identity in morphType:key format (e.g. user:123)}
                                    {role : Role name to revoke}
        EOD;

    /** @var string The console command description. */
    protected $description = 'Revoke a platform-wide role, or one of the resolved tenant\'s, from an authorizable identity';

    /**
     * Execute the console command.
     *
     * @param  \SineMacula\Laravel\Authorization\Services\GrantService  $grants
     * @return int
     */
    public function handle(GrantService $grants): int
    {
        /** @var string $identityArg */
        $identityArg = $this->argument('identity');

        /** @var string $roleName */
        $roleName = $this->argument('role');

        $model = $this->resolveIdentity($identityArg);

        if ($model === null) {
            return self::FAILURE;
        }

        try {
            $revoked = $grants->revokeRole($model, $roleName);
        } catch (\Throwable $e) {
            $this->error($e->getMessage());

            return self::FAILURE;
        }

        $this->info($revoked > 0 ? "Role '{$roleName}' revoked from {$identityArg}." : "{$identityArg} does not hold role '{$roleName}'.");

        return self::SUCCESS;
    }
}
