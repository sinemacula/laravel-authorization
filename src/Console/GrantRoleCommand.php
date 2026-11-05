<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Console;

use Illuminate\Console\Command;
use SineMacula\Laravel\Authorization\Console\Concerns\ResolvesIdentity;

/**
 * Assign a role to an authorizable identity.
 *
 * Accepts the identity as `{morphType}:{key}` (e.g. `user:123`) and the role by
 * name. Resolves the morph alias via the Eloquent morph map, validates the
 * `AuthorizableIdentity` contract, and delegates to `assignRole()`.
 *
 * The role name is looked up within the tenant scope, like any other query: a
 * tenant-owned role is found only when the application's subject resolver
 * resolves its tenant in the console, and then ranks before a platform-wide
 * role of the same name, which is assigned only when the tenant owns none.
 * Without a tenant, only platform-wide roles can be assigned.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class GrantRoleCommand extends Command
{
    use ResolvesIdentity;

    /** @var string The console command signature. */
    protected $signature = <<<'EOD'
        authorization:grant
                                    {identity : Identity in morphType:key format (e.g. user:123)}
                                    {role : Role name to assign}
        EOD;

    /** @var string The console command description. */
    protected $description = 'Assign a platform-wide role, or one of the resolved tenant\'s, to an authorizable identity';

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
            $model->assignRole($roleName);
        } catch (\Throwable $e) { // @phpstan-ignore catch.neverThrown
            $this->error($e->getMessage());

            return self::FAILURE;
        }

        $this->info("Role '{$roleName}' granted to {$identityArg}.");

        return self::SUCCESS;
    }
}
