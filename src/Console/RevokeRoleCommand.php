<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Console;

use Illuminate\Console\Command;
use SineMacula\Laravel\Authorization\Console\Concerns\ResolvesIdentity;

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
class RevokeRoleCommand extends Command
{
    use ResolvesIdentity;

    /**
     * The console command signature.
     *
     * @var string
     */
    protected $signature = <<<'EOD'
        authorization:revoke
                                    {identity : Identity in morphType:key format (e.g. user:123)}
                                    {role : Role name to revoke}
        EOD;

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Revoke a role from an authorizable identity';

    /**
     * Execute the console command.
     *
     * @return int
     */
    public function handle(): int
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
            $model->revokeRole($roleName);
        } catch (\Throwable $e) {
            $this->error($e->getMessage());

            return self::FAILURE;
        }

        $this->info("Role '{$roleName}' revoked from {$identityArg}.");

        return self::SUCCESS;
    }
}
