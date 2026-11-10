<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Config;

use Illuminate\Container\Container;
use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;

/**
 * Read a setting of the authorization config at run time, as the configuration
 * holds it now.
 *
 * Boot validates every setting, but the configuration can change after boot, so
 * a reader never falls back to a default for a value it cannot use: it refuses
 * it, naming its path, the way boot would. A setting the configuration leaves
 * out takes its default, while one set inside a block that is not an array is
 * refused, so a malformed block is never read as a missing one.
 *
 * Each read is a walk down the arrays that hold the setting, with no validator
 * run, so a reader on a hot path pays a few array lookups and plain
 * comparisons.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ConfigValue
{
    /** @var string The key of the authorization config. */
    public const string ROOT = 'authorization';

    /**
     * Return the setting at the path below `authorization`, or the default when
     * the configuration leaves it out, refusing a block on the way that is not
     * an array. The bound configuration is read, or none when no configuration
     * is bound, as in library-mode embedding.
     *
     * @param  string  $path
     * @param  mixed  $default
     * @param  \Illuminate\Contracts\Config\Repository|null  $config
     * @return mixed
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function get(string $path, mixed $default = null, ?Repository $config = null): mixed
    {
        $config ??= self::config();

        if ($config === null || !$config->has(self::ROOT)) {
            return $default;
        }

        $value  = $config->get(self::ROOT);
        $walked = self::ROOT;

        foreach (\explode('.', $path) as $key) {
            if (!\is_array($value)) {
                throw new InvalidAuthorizationConfigException($walked, 'expected an array, got ' . ConfigValidator::describe($value) . '.');
            }

            if (!\array_key_exists($key, $value)) {
                return $default;
            }

            $value  = $value[$key];
            $walked = "{$walked}.{$key}";
        }

        return $value;
    }

    /**
     * Return the block at the path below `authorization`, empty when the
     * configuration leaves it out, refusing one that is not an array.
     *
     * @param  string  $path
     * @param  \Illuminate\Contracts\Config\Repository|null  $config
     * @return array<array-key, mixed>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function block(string $path, ?Repository $config = null): array
    {
        $block = self::get($path, [], $config);

        return \is_array($block)
            ? $block
            : throw new InvalidAuthorizationConfigException(self::ROOT . ".{$path}", 'expected an array, got ' . ConfigValidator::describe($block) . '.');
    }

    /**
     * Return the name at the path below `authorization`, or the default when
     * the configuration leaves it out, refusing a value that is not a non-empty
     * string, with what was expected, rather than reading it as the default.
     * The value is checked with plain type checks, with no pattern matched.
     *
     * @param  string  $path
     * @param  string  $default
     * @param  string  $expected
     * @param  \Illuminate\Contracts\Config\Repository|null  $config
     * @return non-empty-string
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function name(string $path, string $default, string $expected, ?Repository $config = null): string
    {
        $value = self::get($path, $default, $config);

        return \is_string($value) && $value !== ''
            ? $value
            : throw new InvalidAuthorizationConfigException(self::ROOT . ".{$path}", "expected {$expected}, got " . ConfigValidator::describe($value) . '.');
    }

    /**
     * Return the whole-number setting at the path below `authorization`, or the
     * default when the configuration leaves it out, refusing a value that is
     * not a whole number of at least the least allowed (see `IntegerSetting`).
     * A PHP int is checked with plain comparisons.
     *
     * @param  string  $path
     * @param  int  $default
     * @param  int  $least
     * @return int
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function integer(string $path, int $default, int $least): int
    {
        return self::integerOf(self::ROOT . ".{$path}", self::get($path, $default), $least);
    }

    /**
     * Return the value as a whole number of at least the least allowed,
     * refusing it, under its path, otherwise. A PHP int is checked with plain
     * comparisons, with no pattern matched.
     *
     * @param  string  $path
     * @param  mixed  $value
     * @param  int  $least
     * @return int
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function integerOf(string $path, mixed $value, int $least): int
    {
        return IntegerSetting::require($path, $value, $least);
    }

    /**
     * Return the bound configuration, or null when none is bound.
     *
     * @return \Illuminate\Contracts\Config\Repository|null
     */
    private static function config(): ?Repository
    {
        $container = Container::getInstance();

        $config = $container->bound('config') ? $container->make('config') : null;

        return $config instanceof Repository ? $config : null;
    }
}
