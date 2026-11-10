<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Console;

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
    /** @var string The console command's name. */
    public const string NAME = 'authorization:list-permissions';

    /** @var string The `authorization.models` key of the listed model. */
    protected const string MODEL = 'permission';
}
