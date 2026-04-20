<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Console;

use Illuminate\Database\Eloquent\Model;
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
final class ListRolesCommand extends AbstractListCatalogueCommand
{
    /** @var string The console command signature. */
    protected $signature = 'authorization:list-roles {--guard= : Filter roles by guard name}';

    /** @var string The console command description. */
    protected $description = 'List all authorization roles';

    /**
     * Resolve the configured role model class.
     *
     * @return class-string<\Illuminate\Database\Eloquent\Model>
     */
    #[\Override]
    protected function modelClass(): string
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Role> */
        return config('authorization.models.role', Role::class);
    }

    /**
     * Relation to include via `withCount`.
     *
     * @return string
     */
    #[\Override]
    protected function countRelation(): string
    {
        return 'permissions';
    }

    /**
     * Message rendered when no roles match the query.
     *
     * @return string
     */
    #[\Override]
    protected function emptyMessage(): string
    {
        return 'No roles found.';
    }

    /**
     * Table header row.
     *
     * @return list<string>
     */
    #[\Override]
    protected function headers(): array
    {
        return ['ID', 'Name', 'Guard', 'System', 'Permissions'];
    }

    /**
     * Map a role row to the table columns.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $row
     * @return list<string>
     */
    #[\Override]
    protected function mapRow(Model $row): array
    {
        /** @var \SineMacula\Laravel\Authorization\Models\Role $row */
        /** @var int $count */
        $count = $row->getAttribute('permissions_count');

        return [
            $row->id,
            $row->name,
            $row->guard ?? '(any)',
            $row->is_system ? 'Yes' : 'No',
            (string) $count,
        ];
    }
}
