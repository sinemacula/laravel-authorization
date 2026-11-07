<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Config;

use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;

/**
 * Boot-time validator for the `authorization.bulk` config (AUTHZ-10.3), run by
 * `ConfigValidator`.
 *
 * The block must be an array, and the chunk size it sets (`chunk_size`), how
 * many checks of a bulk check are read for at a time, a whole number of at
 * least 1. A block that does not set it takes its default; any other key is
 * refused, so a misspelt key fails at boot rather than leaving the default in
 * place.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class BulkConfigValidator
{
    /** @var string The config key of the block. */
    public const string KEY = 'authorization.bulk';

    /** @var list<string> The keys the block may set. */
    public const array KEYS = ['chunk_size'];

    /**
     * Validate the supplied `bulk` config, throwing on the first failure.
     *
     * @param  mixed  $config
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function validate(mixed $config): void
    {
        $block   = \is_array($config) ? $config : throw new InvalidAuthorizationConfigException(self::KEY, 'expected an array, got ' . self::describe($config) . '.');
        $unknown = \array_values(\array_diff(\array_map(strval(...), \array_keys($block)), self::KEYS));

        if ($unknown !== []) {
            throw new InvalidAuthorizationConfigException(self::KEY, "unknown key '{$unknown[0]}'; expected one of " . \implode(', ', self::KEYS) . '.');
        }

        $size = $block['chunk_size'] ?? 1;

        if (!\is_int($size) || $size < 1) {
            throw new InvalidAuthorizationConfigException(self::KEY . '.chunk_size', 'expected a whole number of at least 1, got ' . self::describe($size) . '.');
        }
    }

    /**
     * Describe a value for a message: a scalar as its literal, anything else by
     * its type, each followed by its type.
     *
     * @param  mixed  $value
     * @return string
     */
    private static function describe(mixed $value): string
    {
        return \var_export(\is_scalar($value) ? $value : \get_debug_type($value), true) . ' (' . \get_debug_type($value) . ')';
    }
}
