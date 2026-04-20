<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Console;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authorization\Models\Permission;

/**
 * List all permissions in a tabular format.
 *
 * Outputs every permission row with its ID, name, guard, system
 * flag, and attached role count. An optional `--guard` filter
 * restricts the listing to a single guard name.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class ListPermissionsCommand extends AbstractListCatalogueCommand
{
    /** @var string The console command signature. */
    protected $signature = 'authorization:list-permissions {--guard= : Filter permissions by guard name}';

    /** @var string The console command description. */
    protected $description = 'List all authorization permissions';

    /**
     * Resolve the configured permission model class.
     *
     * @return class-string<\Illuminate\Database\Eloquent\Model>
     */
    #[\Override]
    protected function modelClass(): string
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Permission> */
        return config('authorization.models.permission', Permission::class);
    }

    /**
     * Relation to include via `withCount`.
     *
     * @return string
     */
    #[\Override]
    protected function countRelation(): string
    {
        return 'roles';
    }

    /**
     * Message rendered when no permissions match the query.
     *
     * @return string
     */
    #[\Override]
    protected function emptyMessage(): string
    {
        return 'No permissions found.';
    }

    /**
     * Table header row.
     *
     * @return list<string>
     */
    #[\Override]
    protected function headers(): array
    {
        return ['ID', 'Name', 'Guard', 'System', 'Roles'];
    }

    /**
     * Map a permission row to the table columns.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $row
     * @return list<string>
     */
    #[\Override]
    protected function mapRow(Model $row): array
    {
        /** @var \SineMacula\Laravel\Authorization\Models\Permission $row */
        /** @var int $count */
        $count = $row->getAttribute('roles_count');

        return [
            $row->id,
            $row->name,
            $row->guard ?? '(any)',
            $row->is_system ? 'Yes' : 'No',
            (string) $count,
        ];
    }
}
