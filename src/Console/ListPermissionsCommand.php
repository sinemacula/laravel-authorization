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
    /** @var string The `authorization.models` key of the listed model. */
    protected const string MODEL = 'permission';

    /** @var class-string<\SineMacula\Laravel\Authorization\Models\Permission> The model listed when none is configured. */
    protected const string DEFAULT_MODEL = Permission::class;

    /** @var string The relation whose records are counted. */
    protected const string COUNTED = 'roles';

    /** @var string The plural name of the listed records. */
    protected const string RECORDS = 'permissions';

    /** @var string The console command signature. */
    protected $signature = <<<'EOD'
        authorization:list-permissions
                                    {--guard= : Filter permissions by guard name}
        EOD;

    /** @var string The console command description. */
    protected $description = 'List every authorization permission, platform-wide and tenant-owned, with its owner';
}
