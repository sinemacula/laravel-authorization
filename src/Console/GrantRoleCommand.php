<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Console;

use Illuminate\Console\Command;
use SineMacula\Laravel\Authorization\Console\Concerns\ResolvesIdentity;
use SineMacula\Laravel\Authorization\Console\Support\ActorOption;
use SineMacula\Laravel\Authorization\Services\GrantService;

/**
 * Assign a role to an authorizable identity.
 *
 * Accepts the identity as `{morphType}:{key}` (e.g. `user:123`) and the role by
 * name. Resolves the morph alias via the Eloquent morph map, validates the
 * `AuthorizableIdentity` contract, and grants the role through the grant
 * service, with no expiry. A role the identity already holds with no expiry is
 * reported as held, and nothing is written; a role it holds on a temporary or
 * expired grant is made permanent and reported as granted.
 *
 * `--actor={morphType}:{key}` names the actor making the change: the grant is
 * then delegated administration, decided as that actor under
 * `authorization:role.grant` (see `GrantService`), with no session: the actor
 * must be senior to the identity, and able to hand out the role's whole
 * authority, or the grant is refused and nothing is written. A grant it makes
 * carries the actor in its event, and its row records it. Without it the grant
 * is trusted system work and records no actor (N75).
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
                                    {--actor= : The actor the change is decided as, in morphType:key format (e.g. user:1); none for trusted system work}
        EOD;

    /** @var string The console command description. */
    protected $description = 'Assign a platform-wide role, or one of the resolved tenant\'s, to an authorizable identity';

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
            $outcome = $grants->grantRole($model, $roleName, actor: ActorOption::acting($this->option('actor')));
        } catch (\Throwable $e) {
            $this->error($e->getMessage());

            return self::FAILURE;
        }

        $this->info($outcome->isChange() ? "Role '{$roleName}' granted to {$identityArg}." : "{$identityArg} already holds role '{$roleName}'.");

        return self::SUCCESS;
    }
}
