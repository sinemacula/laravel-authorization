<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Config;

use Illuminate\Contracts\Config\Repository;

/**
 * Read the class of a package model, as `authorization.models` configures it at
 * run time.
 *
 * A model the block leaves out is the package's own
 * (`ConfigValidator::MODELS`). A block that is not an array, or a class that is
 * not a non-empty string, is refused with
 * `InvalidAuthorizationConfigException`, naming its path, rather than read as
 * the package's model. Boot checks that each class exists and extends the
 * package's model; a read pays only a few array lookups and type checks.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ModelClasses
{
    /**
     * Return the class of the model under the key, `role`, `permission` or
     * `policy`, or the package's model when the configuration leaves it out.
     *
     * @param  'permission'|'policy'|'role'  $key
     * @param  \Illuminate\Contracts\Config\Repository|null  $config
     * @return non-empty-string
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function get(string $key, ?Repository $config = null): string
    {
        return ConfigValue::name("models.{$key}", ConfigValidator::MODELS[$key], 'a class-string', $config);
    }
}
