<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Config;

use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;
use SineMacula\Laravel\Authorization\Reviews\ReviewQuery;

/**
 * Boot-time validator for the `authorization.reviews` config (AUTHZ-11.6), run
 * by `ConfigValidator`.
 *
 * The block must be an array, and its one setting, `limit`, the most rows an
 * access review returns unless it sets its own (see `Reviews\ReviewQuery`), a
 * whole number of at least 1. A block that does not set it takes the default;
 * any other key is refused, so a misspelt setting fails at boot rather than
 * leaving the default in place. The same check refuses a limit changed after
 * boot when a review reads it, so a review never falls back to another bound.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ReviewConfigValidator
{
    /** @var string The config key of the block. */
    public const string KEY = 'authorization.reviews';

    /** @var list<string> The settings the block may set. */
    public const array SETTINGS = ['limit'];

    /**
     * Validate the supplied `reviews` config, throwing on the first failure.
     *
     * @param  mixed  $config
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function validate(mixed $config): void
    {
        if (!\is_array($config)) {
            throw new InvalidAuthorizationConfigException(self::KEY, 'expected an array of settings, got ' . self::describe($config) . '.');
        }

        $unknown = \array_values(\array_diff(\array_keys($config), self::SETTINGS));

        if ($unknown !== []) {
            throw new InvalidAuthorizationConfigException(self::KEY, "unknown setting '{$unknown[0]}'; expected one of " . \implode(', ', self::SETTINGS) . '.');
        }

        self::limit(\array_key_exists('limit', $config) ? $config['limit'] : ReviewQuery::DEFAULT_LIMIT);
    }

    /**
     * Return the limit, refusing one that is not a whole number of at least 1
     * under its key.
     *
     * @param  mixed  $limit
     * @return int
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function limit(mixed $limit): int
    {
        if (\is_int($limit) && $limit >= 1) {
            return $limit;
        }

        throw new InvalidAuthorizationConfigException(self::KEY . '.limit', 'expected a whole number of at least 1, got ' . self::describe($limit) . '.');
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
