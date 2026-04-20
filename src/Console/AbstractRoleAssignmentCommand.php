<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Console;

use Illuminate\Console\Command;
use SineMacula\Laravel\Authorization\Console\Concerns\ResolvesIdentity;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableIdentity;

/**
 * Shared scaffolding for `authorization:grant` and `authorization:revoke`. Both
 * commands share an identical argument shape, identity-resolution step,
 * try/catch wrap, and success message pattern; the concrete subclass supplies
 * only the mutating model call and the success verb.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
abstract class AbstractRoleAssignmentCommand extends Command
{
    use ResolvesIdentity;

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
            $this->mutate($model, $roleName);
        } catch (\Throwable $e) {
            $this->error($e->getMessage());

            return self::FAILURE;
        }

        $this->info($this->successMessage($roleName, $identityArg));

        return self::SUCCESS;
    }

    /**
     * Perform the grant or revoke on the resolved identity.
     *
     * @param  \SineMacula\Laravel\Authorization\Contracts\AuthorizableIdentity  $model
     * @param  string  $roleName
     * @return void
     */
    abstract protected function mutate(AuthorizableIdentity $model, string $roleName): void;

    /**
     * Build the success message written to stdout.
     *
     * @param  string  $roleName
     * @param  string  $identityArg
     * @return string
     */
    abstract protected function successMessage(string $roleName, string $identityArg): string;
}
