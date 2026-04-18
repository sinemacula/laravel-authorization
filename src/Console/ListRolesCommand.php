<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Console;

use Illuminate\Console\Command;
use SineMacula\Laravel\Authorization\Models\Role;

/**
 * List all roles in a tabular format.
 *
 * Outputs every role row with its ID, name, guard, system flag,
 * and attached permission count. An optional `--guard` filter
 * restricts the listing to a single guard name.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
class ListRolesCommand extends Command
{
    /** @var string The console command signature. */
    protected $signature = <<<'EOD'
        authorization:list-roles
                                    {--guard= : Filter roles by guard name}
        EOD;

    /** @var string The console command description. */
    protected $description = 'List all authorization roles';

    /**
     * Execute the console command.
     *
     * @return int
     */
    public function handle(): int
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Role> $class */
        $class = config('authorization.models.role', Role::class);

        $query = $class::query()->withCount('permissions');

        /** @var string|null $guard */
        $guard = $this->option('guard');

        if ($guard !== null && $guard !== '') {
            $query->where('guard_name', $guard);
        }

        /** @var \Illuminate\Database\Eloquent\Collection<int, \SineMacula\Laravel\Authorization\Models\Role> $roles */
        // @phpstan-ignore staticMethod.dynamicCall
        $roles = $query->orderBy('name')->get();

        if ($roles->isEmpty()) {
            $this->info('No roles found.');

            return self::SUCCESS;
        }

        $this->table(
            ['ID', 'Name', 'Guard', 'System', 'Permissions'],
            $roles->map(static function (Role $role): array {
                /** @var int $count */
                $count = $role->getAttribute('permissions_count');

                return [
                    $role->id,
                    $role->name,
                    $role->guard_name ?? '(any)',
                    $role->is_system ? 'Yes' : 'No',
                    (string) $count,
                ];
            })->all(),
        );

        return self::SUCCESS;
    }
}
