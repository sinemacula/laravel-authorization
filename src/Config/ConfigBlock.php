<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Config;

use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;

/**
 * Read a block of the authorization config whose keys the package defines
 * (N116).
 *
 * A block must be an array, and every key it sets must be one the package
 * defines, so a misspelt key is refused at boot, naming its full path, rather
 * than leaving its default in place. A key the block leaves out takes its
 * default; a key set to null is passed on as null, for the setting's own check
 * to refuse unless null means off or none there.
 *
 * Maps the application defines, such as `context.keys` or `session.scopes`, are
 * not blocks: each of their entries is checked against its own shape instead.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ConfigBlock
{
    /**
     * Return the block, refusing a value that is not an array, or that sets a
     * key the package does not define, under the full path.
     *
     * @param  string  $path
     * @param  mixed  $value
     * @param  list<string>  $keys
     * @return array<array-key, mixed>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function of(string $path, mixed $value, array $keys): array
    {
        if (!\is_array($value)) {
            throw new InvalidAuthorizationConfigException($path, 'expected an array, got ' . ConfigValidator::describe($value) . '.');
        }

        foreach (\array_keys($value) as $key) {
            if (!\in_array($key, $keys, true)) {
                throw new InvalidAuthorizationConfigException("{$path}.{$key}", "unknown key '{$key}'; expected one of " . \implode(', ', $keys) . '.');
            }
        }

        return $value;
    }

    /**
     * Return the value the block sets for the key, or the default when the key
     * is left out. A key set to null is returned as null.
     *
     * @param  array<array-key, mixed>  $block
     * @param  string  $key
     * @param  mixed  $default
     * @return mixed
     */
    public static function entry(array $block, string $key, mixed $default): mixed
    {
        return \array_key_exists($key, $block) ? $block[$key] : $default;
    }
}
