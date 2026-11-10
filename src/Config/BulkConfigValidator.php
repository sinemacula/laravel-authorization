<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Config;

/**
 * Boot-time validator for the `authorization.bulk` config (AUTHZ-10.3), run by
 * `ConfigValidator`.
 *
 * The block must be an array, and the chunk size it sets (`chunk_size`), how
 * many checks of a bulk check are read for at a time, a whole number of at
 * least 1, an int or a string written as a whole number, as the environment
 * gives one (N117). A block that does not set it takes its default, and one
 * that sets it to null is refused; any other key is refused, naming its path
 * (N116), so a misspelt key fails at boot rather than leaving the default in
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
        $block = ConfigBlock::of(self::KEY, $config, self::KEYS);

        if (!\array_key_exists('chunk_size', $block)) {
            return;
        }

        IntegerSetting::require(self::KEY . '.chunk_size', $block['chunk_size'], 1);
    }
}
