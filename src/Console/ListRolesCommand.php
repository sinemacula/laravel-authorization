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
    /** @var string The `authorization.models` key of the listed model. */
    protected const string MODEL = 'role';

    /** @var class-string<\SineMacula\Laravel\Authorization\Models\Role> The model listed when none is configured. */
    protected const string DEFAULT_MODEL = Role::class;

    /** @var string The relation whose records are counted. */
    protected const string COUNTED = 'permissions';

    /** @var string The plural name of the listed records. */
    protected const string RECORDS = 'roles';

    /** @var string The console command signature. */
    protected $signature = <<<'EOD'
        authorization:list-roles
                                    {--guard= : Filter roles by guard name}
        EOD;

    /** @var string The console command description. */
    protected $description = 'List every authorization role, platform-wide and tenant-owned, with its owner';
}
