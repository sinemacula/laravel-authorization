<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Console;

use Illuminate\Console\Command;
use SineMacula\Laravel\Authorization\Console\Concerns\ResolvesGrantee;
use SineMacula\Laravel\Authorization\Console\Support\ActorOption;
use SineMacula\Laravel\Authorization\Services\GrantService;

/**
 * Assign a role to a grantee.
 *
 * Accepts the grantee as `{morphType}:{key}` (e.g. `user:123`) and the role by
 * name. Resolves the morph alias via the Eloquent morph map, validates the
 * `AuthorizableGrantee` contract, and grants the role through the grant
 * service, with no expiry. A role the grantee already holds with no expiry is
 * reported as held, and nothing is written; a role it holds on a temporary or
 * expired grant is made permanent and reported as granted.
 *
 * `--actor={morphType}:{key}` names the actor making the change: the grant is
 * then delegated administration, decided as that actor under
 * `authorization:role.grant` (see `GrantService`), with no session: the actor
 * must be senior to the grantee, and able to hand out the role's whole
 * authority, or the grant is refused and nothing is written. A grant it makes
 * carries the actor in its event, and its row records it. Without it the grant
 * is trusted system work and records no actor.
 *
 * A grant that would leave the grantee, alone or with its identity or its
 * principals, holding both roles of a declared pair where their reach overlaps
 * is refused, trusted or not: the command writes the refusal's message and
 * fails, as for any other refusal, and nothing is written.
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
    use ResolvesGrantee;

    /** @var string The console command's name. */
    public const string NAME = 'authorization:grant';

    /** @var string The console command signature. */
    protected $signature = self::NAME . <<<'EOD'

                                    {grantee : Grantee in morphType:key format (e.g. user:123)}
                                    {role : Role name to assign}
                                    {--actor= : The actor the change is decided as, in morphType:key format (e.g. user:1); none for trusted system work}
        EOD;

    /** @var string The console command description. */
    protected $description = 'Assign a platform-wide role, or one of the resolved tenant\'s, to a grantee';

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
            $outcome = $grants->grantRole($model, $roleName, actor: ActorOption::acting($this->option('actor')));
        } catch (\Throwable $e) {
            $this->error($e->getMessage());

            return self::FAILURE;
        }

        $this->info($outcome->isChange() ? "Role '{$roleName}' granted to {$granteeArg}." : "{$granteeArg} already holds role '{$roleName}'.");

        return self::SUCCESS;
    }
}
