<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Console;

use Illuminate\Console\Command;
use SineMacula\Laravel\Authorization\Models\Permission;

/**
 * List all permissions in a tabular format.
 *
 * Outputs every permission row with its ID, name, guard, system flag, and
 * attached role count. An optional `--guard` filter restricts the listing to a
 * single guard name.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class ListPermissionsCommand extends Command
{
    /** @var string The console command signature. */
    protected $signature = <<<'EOD'
        authorization:list-permissions
                                    {--guard= : Filter permissions by guard name}
        EOD;

    /** @var string The console command description. */
    protected $description = 'List all authorization permissions';

    /**
     * Execute the console command.
     *
     * @return int
     */
    public function handle(): int
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Permission> $class */
        $class = config('authorization.models.permission', Permission::class);

        $query = $class::query()->withCount('roles');

        /** @var string|null $guard */
        $guard = $this->option('guard');

        if ($guard !== null && $guard !== '') {
            $query->where('guard_name', $guard);
        }

        /** @var \Illuminate\Database\Eloquent\Collection<int, \SineMacula\Laravel\Authorization\Models\Permission> $permissions */
        // @phpstan-ignore staticMethod.dynamicCall
        $permissions = $query->orderBy('name')->get();

        if ($permissions->isEmpty()) {
            $this->info('No permissions found.');

            return self::SUCCESS;
        }

        $this->table(
            ['ID', 'Name', 'Guard', 'System', 'Roles'],
            $permissions->map(static function (Permission $permission): array {
                /** @var int $count */
                $count = $permission->getAttribute('roles_count');

                return [
                    $permission->id,
                    $permission->name,
                    $permission->guard_name ?? '(any)',
                    $permission->is_system ? 'Yes' : 'No',
                    (string) $count,
                ];
            })->all(),
        );

        return self::SUCCESS;
    }
}
