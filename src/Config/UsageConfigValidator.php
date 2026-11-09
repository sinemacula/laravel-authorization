<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Config;

use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;

/**
 * Boot-time validator for the `authorization.usage` config (N94, N101), run by
 * `ConfigValidator`.
 *
 * The block must be an array of these settings, each optional:
 *
 * - `enabled`: whether grant usage is tracked, a boolean, false by default;
 * - `interval`: the length of a usage bucket in seconds, a whole number of at
 *   least 60, 3600 by default;
 * - `batch`: how many observations a worker holds before it flushes them, a
 *   whole number of at least 1, 1000 by default;
 * - `connection` and `queue`: the queue connection and queue the recording job
 *   is sent to, each a non-empty string or null for the default;
 * - `retention`: how many days coverage is kept, a whole number of at least 1,
 *   400 by default.
 *
 * Any other key is refused, so a misspelt setting fails at boot rather than
 * leaving the default in place. The same checks refuse a setting changed after
 * boot when it is read (see `Usage\UsageTracking`).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class UsageConfigValidator
{
    /** @var string The config key of the block. */
    public const string KEY = 'authorization.usage';

    /** @var array<string, int> The whole-number settings, each with its least value. */
    public const array WHOLE = ['interval' => 60, 'batch' => 1, 'retention' => 1];

    /** @var list<string> The settings the block may set. */
    public const array SETTINGS = ['enabled', 'interval', 'batch', 'connection', 'queue', 'retention'];

    /**
     * Validate the `usage` block of the supplied authorization config, a
     * missing block as an empty one, throwing on the first failure.
     *
     * @param  array<string, mixed>  $config
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function validateIn(array $config): void
    {
        self::validate($config['usage'] ?? []);
    }

    /**
     * Validate the supplied `usage` config, throwing on the first failure.
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

        self::enabled($config['enabled'] ?? false);

        foreach (\array_keys(self::WHOLE) as $setting) {
            if (!\array_key_exists($setting, $config)) {
                continue;
            }

            self::whole($setting, $config[$setting]);
        }

        self::name('connection', $config['connection'] ?? null);
        self::name('queue', $config['queue'] ?? null);
    }

    /**
     * Return whether tracking is enabled, refusing a value that is not a
     * boolean.
     *
     * @param  mixed  $enabled
     * @return bool
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function enabled(mixed $enabled): bool
    {
        return \is_bool($enabled) ? $enabled : throw new InvalidAuthorizationConfigException(self::KEY . '.enabled', 'expected a boolean, got ' . self::describe($enabled) . '.');
    }

    /**
     * Return the whole-number setting, refusing one below its least value.
     *
     * @param  string  $setting
     * @param  mixed  $value
     * @return int
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function whole(string $setting, mixed $value): int
    {
        $least = self::WHOLE[$setting] ?? 1;

        if (\is_int($value) && $value >= $least) {
            return $value;
        }

        throw new InvalidAuthorizationConfigException(self::KEY . '.' . $setting, "expected a whole number of at least {$least}, got " . self::describe($value) . '.');
    }

    /**
     * Return the named queue connection or queue, refusing anything but a
     * non-empty string or null.
     *
     * @param  string  $setting
     * @param  mixed  $value
     * @return string|null
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function name(string $setting, mixed $value): ?string
    {
        if ($value === null || (\is_string($value) && $value !== '')) {
            return $value;
        }

        throw new InvalidAuthorizationConfigException(self::KEY . '.' . $setting, 'expected a non-empty string or null, got ' . self::describe($value) . '.');
    }

    /**
     * Describe a value for a message: a scalar as JSON, anything else by its
     * type, each followed by its type.
     *
     * @param  mixed  $value
     * @return string
     */
    private static function describe(mixed $value): string
    {
        $shown = \is_scalar($value) ? \json_encode($value, \JSON_UNESCAPED_SLASHES | \JSON_INVALID_UTF8_SUBSTITUTE) : \get_debug_type($value);

        return $shown . ' (' . \get_debug_type($value) . ')';
    }
}
