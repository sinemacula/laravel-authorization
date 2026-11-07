<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Config;

use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;

/**
 * Boot-time validator for the `authorization.query_scoping` config
 * (AUTHZ-10.1), run by `ConfigValidator`.
 *
 * The block must be an array, and each limit it sets (`max_anchors`,
 * `max_scopes`, `max_attachments`) a whole number of at least 1. A limit it
 * does not set takes its default; any other key is refused, so a misspelt limit
 * fails at boot rather than leaving its default in place.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class QueryScopingConfigValidator
{
    /** @var string The config key of the block. */
    public const string KEY = 'authorization.query_scoping';

    /** @var list<string> The limits the block may set. */
    public const array LIMITS = ['max_anchors', 'max_scopes', 'max_attachments'];

    /**
     * Validate the supplied `query_scoping` config, throwing on the first
     * failure.
     *
     * @param  mixed  $config
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function validate(mixed $config): void
    {
        if (!\is_array($config)) {
            throw new InvalidAuthorizationConfigException(self::KEY, 'expected an array of limits, got ' . self::describe($config) . '.');
        }

        foreach ($config as $key => $limit) {
            if (!\in_array($key, self::LIMITS, true)) {
                throw new InvalidAuthorizationConfigException(self::KEY, "unknown limit '{$key}'; expected one of " . \implode(', ', self::LIMITS) . '.');
            }

            if (!\is_int($limit) || $limit < 1) {
                throw new InvalidAuthorizationConfigException(self::KEY . ".{$key}", 'expected a whole number of at least 1, got ' . self::describe($limit) . '.');
            }
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
