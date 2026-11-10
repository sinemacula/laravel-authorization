<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Config;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\IssueCode;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;

/**
 * Validator and reader of the `authorization.cache` config, run by
 * `ConfigValidator`.
 *
 * The block must be an array of these settings, each optional:
 *
 * - `store`: the cache store resolutions persist in across requests, a store
 *   the cache manager resolves, or null, the default, for none;
 * - `ttl`: the longest an entry lives, a whole number of seconds of at least 1
 *   (N117), 300 by default; null is refused, as there is no "forever": an entry
 *   that missed an invalidation would otherwise never heal;
 * - `prefix`: the prefix of every key the cache writes, a non-empty string,
 *   `authorization` by default.
 *
 * Any other key is refused (N116). The resolution cache reads the lifetime and
 * the prefix through the same checks when it is built, so a value changed after
 * boot is refused there too.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CacheConfigValidator
{
    /** @var string The config key of the block. */
    public const string KEY = 'authorization.cache';

    /** @var list<string> The settings the block may set. */
    public const array SETTINGS = ['store', 'ttl', 'prefix'];

    /** @var int The longest an entry lives, in seconds, when `ttl` is not set. */
    public const int TTL = 300;

    /** @var string The prefix of every key when `prefix` is not set. */
    public const string PREFIX = 'authorization';

    /**
     * Validate the supplied `cache` config, throwing on the first failure.
     *
     * @param  mixed  $config
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function validate(mixed $config, Container $container): void
    {
        $block = ConfigBlock::of(self::KEY, $config, self::SETTINGS);

        self::validateStore(ConfigBlock::entry($block, 'store', null), $container);
        self::ttl(ConfigBlock::entry($block, 'ttl', self::TTL));
        self::prefix(ConfigBlock::entry($block, 'prefix', self::PREFIX));
    }

    /**
     * Return the longest an entry lives, refusing a value that is not a whole
     * number of seconds of at least 1.
     *
     * @param  mixed  $ttl
     * @return int
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function ttl(mixed $ttl): int
    {
        return IntegerSetting::require(self::KEY . '.ttl', $ttl, 1, 'a whole number of seconds');
    }

    /**
     * Return the prefix of every key, refusing one that is not a non-empty
     * string.
     *
     * @param  mixed  $prefix
     * @return non-empty-string
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function prefix(mixed $prefix): string
    {
        if (\is_string($prefix) && $prefix !== '') {
            return $prefix;
        }

        $reason = 'expected a non-empty string, got ' . ConfigValidator::describe($prefix) . '.';

        throw new InvalidAuthorizationConfigException(self::KEY . '.prefix', $reason, IssueCode::INVALID_TYPE, 'a non-empty string', \get_debug_type($prefix));
    }

    /**
     * Return the store's name, refusing a value that is neither null nor a
     * non-empty string.
     *
     * @param  mixed  $value
     * @return string|null
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function storeName(mixed $value): ?string
    {
        if ($value === null || (\is_string($value) && $value !== '')) {
            return $value;
        }

        $reason = 'expected a cache-store name string, got ' . ConfigValidator::describe($value) . '.';

        throw new InvalidAuthorizationConfigException(self::KEY . '.store', $reason, IssueCode::INVALID_TYPE, 'a cache store name or null', \get_debug_type($value));
    }

    /**
     * Validate that `cache.store`, when set, resolves through the Laravel cache
     * manager. The cache manager throws on an unknown store name, which is
     * swapped for the typed config exception.
     *
     * @param  mixed  $value
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    private static function validateStore(mixed $value, Container $container): void
    {
        $name = self::storeName($value);

        if ($name === null || !$container->bound('cache')) {
            return;
        }

        try {
            $container->make('cache')->store($name);
        } catch (\Throwable $exception) {
            $reason = "cache store '{$name}' is not configured: " . $exception->getMessage();

            throw new InvalidAuthorizationConfigException(self::KEY . '.store', $reason, IssueCode::UNKNOWN_NAME, 'the name of a configured cache store', 'string');
        }
    }
}
