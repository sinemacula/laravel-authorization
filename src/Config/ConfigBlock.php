<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Config;

use SineMacula\Laravel\Authorization\Diagnostics\Enums\IssueCode;
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
    /** @var string What a block, or a list, is expected to be. */
    public const string ARRAY = 'an array';

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
            $reason = 'expected an array, got ' . ConfigValidator::describe($value) . '.';

            throw new InvalidAuthorizationConfigException($path, $reason, IssueCode::INVALID_TYPE, self::ARRAY, \get_debug_type($value));
        }

        $unknown = self::unknownKeys($value, $keys);

        return $unknown === [] ? $value : throw self::unknownKey($path, $unknown[0], $keys);
    }

    /**
     * Return the array under the path, refusing a value that is not one, after
     * checking each of its entries with the check given, which refuses an entry
     * under its own path.
     *
     * @param  string  $path
     * @param  mixed  $value
     * @param  string  $shape
     * @param  \Closure(array-key, mixed): mixed  $entry
     * @return array<array-key, mixed>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function entries(string $path, mixed $value, string $shape, \Closure $entry): array
    {
        if (!\is_array($value)) {
            $reason = "expected {$shape}, got " . \get_debug_type($value) . '.';

            throw new InvalidAuthorizationConfigException($path, $reason, IssueCode::INVALID_TYPE, $shape, \get_debug_type($value));
        }

        foreach ($value as $key => $item) {
            $entry($key, $item);
        }

        return $value;
    }

    /**
     * Return the keys the block sets that the package does not define, in the
     * order the block sets them, without refusing any.
     *
     * @param  array<array-key, mixed>  $block
     * @param  list<string>  $keys
     * @return list<array-key>
     */
    public static function unknownKeys(array $block, array $keys): array
    {
        return \array_values(\array_filter(\array_keys($block), static fn (int|string $key): bool => !\in_array($key, $keys, true)));
    }

    /**
     * Refuse a key the block sets that the package does not define, under its
     * full path.
     *
     * @param  string  $path
     * @param  int|string  $key
     * @param  list<string>  $keys
     * @return never
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function refuseUnknownKey(string $path, int|string $key, array $keys): never
    {
        throw self::unknownKey($path, $key, $keys);
    }

    /**
     * Return the refusal of a key the block sets that the package does not
     * define, under its full path.
     *
     * @param  string  $path
     * @param  int|string  $key
     * @param  list<string>  $keys
     * @return \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function unknownKey(string $path, int|string $key, array $keys): InvalidAuthorizationConfigException
    {
        $expected = 'one of ' . \implode(', ', $keys);

        return new InvalidAuthorizationConfigException("{$path}.{$key}", "unknown key '{$key}'; expected {$expected}.", IssueCode::UNKNOWN_KEY, $expected);
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
