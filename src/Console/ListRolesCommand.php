<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Console;

use Illuminate\Console\Command;
use Illuminate\Database\Eloquent\Builder;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;

/**
 * List every role in a tabular format.
 *
 * An administrative view: it bypasses the tenant scope, so platform-wide and
 * tenant-owned roles are listed alike, each with its ID, name, guard, owner
 * (`platform`, or the owning tenant as `{morphType}:{key}`), system flag, and
 * attached permission count, which counts every permission whatever its owner.
 * An optional `--guard` filter restricts the listing to a single guard name.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class ListRolesCommand extends Command
{
    /** @var string The console command signature. */
    protected $signature = <<<'EOD'
        authorization:list-roles
                                    {--guard= : Filter roles by guard name}
        EOD;

    /** @var string The console command description. */
    protected $description = 'List every authorization role, platform-wide and tenant-owned, with its owner';

    /**
     * Execute the console command.
     *
     * @return int
     */
    public function handle(): int
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Role> $class */
        $class = config('authorization.models.role', Role::class);

        $query = $class::query()
            ->withoutGlobalScope(TenantScope::class)
            ->withCount(['permissions' => static fn (Builder $permissions): Builder => $permissions->withoutGlobalScope(TenantScope::class)]);

        /** @var string|null $guard */
        $guard = $this->option('guard');

        if ($guard !== null && $guard !== '') {
            $query->where('guard', $guard);
        }

        /** @var \Illuminate\Database\Eloquent\Collection<int, \SineMacula\Laravel\Authorization\Models\Role> $roles */
        // @phpstan-ignore staticMethod.dynamicCall
        $roles = $query->orderBy('name')->get();

        if ($roles->isEmpty()) {
            $this->info('No roles found.');

            return self::SUCCESS;
        }

        $this->table(
            ['ID', 'Name', 'Guard', 'Owner', 'System', 'Permissions'],
            $roles->map(static function (Role $role): array {
                /** @var int $count */
                $count = $role->getAttribute('permissions_count');

                return [
                    $role->id,
                    $role->name,
                    $role->guard ?? '(any)',
                    $role->tenant_type === null ? 'platform' : "{$role->tenant_type}:{$role->tenant_id}",
                    $role->is_system ? 'Yes' : 'No',
                    (string) $count,
                ];
            })->all(),
        );

        return self::SUCCESS;
    }
}
