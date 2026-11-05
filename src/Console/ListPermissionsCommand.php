<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Console;

use Illuminate\Console\Command;
use Illuminate\Database\Eloquent\Builder;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;

/**
 * List every permission in a tabular format.
 *
 * An administrative view: it bypasses the tenant scope, so platform-wide and
 * tenant-owned permissions are listed alike, each with its ID, name, guard,
 * owner (`platform`, or the owning tenant as `{morphType}:{key}`), system flag,
 * and attached role count, which counts every role whatever its owner. An
 * optional `--guard` filter restricts the listing to a single guard name.
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
    protected $description = 'List every authorization permission, platform-wide and tenant-owned, with its owner';

    /**
     * Execute the console command.
     *
     * @return int
     */
    public function handle(): int
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Permission> $class */
        $class = config('authorization.models.permission', Permission::class);

        $query = $class::query()
            ->withoutGlobalScope(TenantScope::class)
            ->withCount(['roles' => static fn (Builder $roles): Builder => $roles->withoutGlobalScope(TenantScope::class)]);

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
            ['ID', 'Name', 'Guard', 'Owner', 'System', 'Roles'],
            $permissions->map(static function (Permission $permission): array {
                /** @var int $count */
                $count = $permission->getAttribute('roles_count');

                return [
                    $permission->id,
                    $permission->name,
                    $permission->guard_name ?? '(any)',
                    $permission->tenant_type === null ? 'platform' : "{$permission->tenant_type}:{$permission->tenant_id}",
                    $permission->is_system ? 'Yes' : 'No',
                    (string) $count,
                ];
            })->all(),
        );

        return self::SUCCESS;
    }
}
