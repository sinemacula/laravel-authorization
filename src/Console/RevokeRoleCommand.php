<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Console;

use Illuminate\Console\Command;
use SineMacula\Laravel\Authorization\Console\Concerns\ResolvesGrantee;
use SineMacula\Laravel\Authorization\Console\Support\ActorOption;
use SineMacula\Laravel\Authorization\Services\GrantService;

/**
 * Revoke a role from a grantee.
 *
 * Accepts the grantee as `{morphType}:{key}` (e.g. `user:123`) and the role by
 * name. Resolves the morph alias via the Eloquent morph map, validates the
 * `AuthorizableGrantee` contract, and revokes the role through the grant
 * service. A role the grantee does not hold is reported as not held.
 *
 * `--actor={morphType}:{key}` names the actor making the change: the revocation
 * is then delegated administration, decided as that actor under
 * `authorization:role.revoke` (see `GrantService`), and its event carries the
 * actor. Without it the revocation is trusted system work and records no actor.
 *
 *
 * The role name is revoked from the roles the grantee holds within the tenant
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
    use ResolvesGrantee;

    /** @var string The console command's name. */
    public const string NAME = 'authorization:revoke';

    /** @var string The console command signature. */
    protected $signature = self::NAME . <<<'EOD'

                                    {grantee : Grantee in morphType:key format (e.g. user:123)}
                                    {role : Role name to revoke}
                                    {--actor= : The actor the change is decided as, in morphType:key format (e.g. user:1); none for trusted system work}
        EOD;

    /** @var string The console command description. */
    protected $description = 'Revoke a platform-wide role, or one of the resolved tenant\'s, from a grantee';

    /**
     * Execute the console command.
     *
     * @param  \SineMacula\Laravel\Authorization\Services\GrantService  $grants
     * @return int
     */
    public function handle(GrantService $grants): int
    {
        /** @var string $granteeArg */
        $granteeArg = $this->argument('grantee');

        /** @var string $roleName */
        $roleName = $this->argument('role');

        $model = $this->resolveGrantee($granteeArg);

        if ($model === null) {
            return self::FAILURE;
        }

        try {
            $revoked = $grants->revokeRole($model, $roleName, ActorOption::acting($this->option('actor')));
        } catch (\Throwable $e) {
            $this->error($e->getMessage());

            return self::FAILURE;
        }

        $this->info($revoked > 0 ? "Role '{$roleName}' revoked from {$granteeArg}." : "{$granteeArg} does not hold role '{$roleName}'.");

        return self::SUCCESS;
    }
}
