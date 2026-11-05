<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Console;

use SineMacula\Laravel\Authorization\Models\Role;

/**
 * List every role in a tabular format.
 *
 * See `ListCatalogueCommand` for what each row shows.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class ListRolesCommand extends ListCatalogueCommand
{
    /** @var string The console command signature. */
    protected $signature = <<<'EOD'
        authorization:list-roles
                                    {--guard= : Filter roles by guard name}
        EOD;

    /** @var string The console command description. */
    protected $description = 'List every authorization role, platform-wide and tenant-owned, with its owner';

    /**
     * The configured role model class.
     *
     * @return class-string<\Illuminate\Database\Eloquent\Model>
     */
    #[\Override]
    protected function modelClass(): string
    {
        // `config()` is typed mixed; the configuration validator has already
        // refused a models.role setting that is not a model class.
        // @phpstan-ignore return.type
        return config('authorization.models.role', Role::class);
    }

    /**
     * Count each role's permissions.
     *
     * @return string
     */
    #[\Override]
    protected function countedRelation(): string
    {
        return 'permissions';
    }

    /**
     * Name the listed records in the empty-listing message.
     *
     * @return string
     */
    #[\Override]
    protected function recordName(): string
    {
        return 'roles';
    }
}
