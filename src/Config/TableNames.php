<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Config;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;

/**
 * Read the name of a package table, as `authorization.tables` names it at run
 * time.
 *
 * A table the block leaves out takes its key as its name, as the config file
 * has it. A name left at its default, the key's own, gets `tables.prefix` put
 * before it; a name set explicitly, one that differs from the key's own, is
 * used as it is written. Whether a name was set explicitly is told by its value
 * alone, as a merged or cached configuration no longer says where a value came
 * from: a name set to the key's own, in the environment or the published file,
 * is the default, and is prefixed.
 *
 * A block that is not an array, a name that is not a non-empty string, or a
 * prefix that is not a string is refused with
 * `InvalidAuthorizationConfigException`, naming its path, rather than read as
 * the package's name for the table, so a renamed table is never swapped for the
 * default one without a word. Boot checks every name and the prefix in full
 * (`TableConfigValidator`); a read pays only a few array lookups and type
 * checks, since every model reads its table when it is built and the hot paths
 * read theirs on every query.
 *
 * Part of the stable API suite packages may use to read the package's settings
 * the way the package itself does; breaking changes require a major version
 * bump.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class TableNames
{
    /** @var string The key of the prefix in the block. */
    public const string PREFIX = 'prefix';

    /**
     * Return the name of the table under the key: the name the configuration
     * sets explicitly, else the key itself with the prefix before it.
     *
     * @param  string  $key
     * @param  \Illuminate\Contracts\Config\Repository|null  $config
     * @return non-empty-string
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function get(string $key, ?Repository $config = null): string
    {
        $tables = ConfigValue::block('tables', $config);
        $name   = ConfigBlock::entry($tables, $key, $key);

        if (!\is_string($name) || $name === '') {
            throw new InvalidAuthorizationConfigException(ConfigValue::ROOT . ".tables.{$key}", 'expected a table name, got ' . ConfigValidator::describe($name) . '.');
        }

        return self::isDefault($key, $name) ? self::prefixOf($tables) . $name : $name;
    }

    /**
     * Return the prefix put before the name of every table left at its default,
     * empty when the configuration leaves it out.
     *
     * @param  \Illuminate\Contracts\Config\Repository|null  $config
     * @return string
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function prefix(?Repository $config = null): string
    {
        return self::prefixOf(ConfigValue::block('tables', $config));
    }

    /**
     * Determine whether the prefix is one the package accepts for
     * `tables.prefix`: empty, or a lower-case letter followed by lower-case
     * letters, digits and underscores, of at most 16 characters, which every
     * default table name has room for. It is the rule boot validation applies,
     * for an installer to check a prefix before writing it.
     *
     * @param  string  $prefix
     * @return bool
     */
    public static function isValidPrefix(string $prefix): bool
    {
        try {
            TableConfigValidator::prefix($prefix);
        } catch (InvalidAuthorizationConfigException) {
            return false;
        }

        return true;
    }

    /**
     * Determine whether the name set under the key is the table's default, the
     * key's own name, and so takes the prefix, rather than a name set
     * explicitly.
     *
     * @param  string  $key
     * @param  mixed  $name
     * @return bool
     */
    public static function isDefault(string $key, mixed $name): bool
    {
        return $name === $key;
    }

    /**
     * Return the prefix the block sets, empty when it leaves it out, refusing
     * one that is not a string.
     *
     * @param  array<array-key, mixed>  $tables
     * @return string
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    private static function prefixOf(array $tables): string
    {
        $prefix = ConfigBlock::entry($tables, self::PREFIX, '');

        if (!\is_string($prefix)) {
            $reason = 'expected a table name prefix, got ' . ConfigValidator::describe($prefix) . '.';

            throw new InvalidAuthorizationConfigException(ConfigValue::ROOT . '.tables.' . self::PREFIX, $reason);
        }

        return $prefix;
    }
}
