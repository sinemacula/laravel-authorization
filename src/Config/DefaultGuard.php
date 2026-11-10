<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Config;

use Illuminate\Contracts\Config\Repository;

/**
 * Read the guard `authorization.defaults.guard` names at run time, which a
 * lookup by name scopes to when it is given none.
 *
 * A guard the block leaves out is `web` (`NamedEntryConfigValidator::GUARD`). A
 * block that is not an array, or a guard that is not a non-empty string, is
 * refused with `InvalidAuthorizationConfigException`, naming its path, rather
 * than read as `web`. Boot checks that the guard names an entry of
 * `auth.guards`; a read pays only a few array lookups and type checks.
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
final class DefaultGuard
{
    /**
     * Return the default guard's name.
     *
     * @param  \Illuminate\Contracts\Config\Repository|null  $config
     * @return non-empty-string
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function get(?Repository $config = null): string
    {
        return ConfigValue::name('defaults.guard', NamedEntryConfigValidator::GUARD, 'a non-empty name', $config);
    }
}
