<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Config;

use Illuminate\Contracts\Config\Repository;

/**
 * Read the name of a package table, as `authorization.tables` names it at run
 * time.
 *
 * A table the block leaves out takes its key as its name, as the config file
 * has it. A block that is not an array, or a name that is not a non-empty
 * string, is refused with `InvalidAuthorizationConfigException`, naming its
 * path, rather than read as the package's name for the table, so a renamed
 * table is never swapped for the default one without a word. Boot checks every
 * name in full (`TableConfigValidator`); a read pays only a few array lookups
 * and type checks, since every model reads its table when it is built and the
 * hot paths read theirs on every query.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class TableNames
{
    /**
     * Return the name of the table under the key, or the key itself when the
     * configuration leaves it out.
     *
     * @param  string  $key
     * @param  \Illuminate\Contracts\Config\Repository|null  $config
     * @return non-empty-string
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function get(string $key, ?Repository $config = null): string
    {
        return ConfigValue::name("tables.{$key}", $key, 'a table name', $config);
    }
}
