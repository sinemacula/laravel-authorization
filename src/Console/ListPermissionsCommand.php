<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Console;

use SineMacula\Laravel\Authorization\Models\Permission;

/**
 * List every permission in a tabular format.
 *
 * See `ListCatalogueCommand` for what each row shows.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class ListPermissionsCommand extends ListCatalogueCommand
{
    /** @var string The console command signature. */
    protected $signature = <<<'EOD'
        authorization:list-permissions
                                    {--guard= : Filter permissions by guard name}
        EOD;

    /** @var string The console command description. */
    protected $description = 'List every authorization permission, platform-wide and tenant-owned, with its owner';

    /**
     * The configured permission model class.
     *
     * @return class-string<\Illuminate\Database\Eloquent\Model>
     */
    #[\Override]
    protected function modelClass(): string
    {
        // `config()` is typed mixed; the configuration validator has already
        // refused a models.permission setting that is not a model class.
        // @phpstan-ignore return.type
        return config('authorization.models.permission', Permission::class);
    }

    /**
     * Count each permission's roles.
     *
     * @return string
     */
    #[\Override]
    protected function countedRelation(): string
    {
        return 'roles';
    }

    /**
     * Name the listed records in the empty-listing message.
     *
     * @return string
     */
    #[\Override]
    protected function recordName(): string
    {
        return 'permissions';
    }
}
