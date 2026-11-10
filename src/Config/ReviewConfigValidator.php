<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Config;

use SineMacula\Laravel\Authorization\Reviews\ReviewQuery;

/**
 * Boot-time validator for the `authorization.reviews` config (AUTHZ-11.6), run
 * by `ConfigValidator`.
 *
 * The block must be an array, and its one setting, `limit`, the most rows an
 * access review returns unless it sets its own (see `Reviews\ReviewQuery`), a
 * whole number of at least 1, an int or a string written as a whole number, as
 * the environment gives one (N117). A block that does not set it takes the
 * default, and one that sets it to null is refused; any other key is refused,
 * naming its path (N116), so a misspelt setting fails at boot rather than
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
        $block = ConfigBlock::of(self::KEY, $config, self::SETTINGS);

        self::limit(ConfigBlock::entry($block, 'limit', ReviewQuery::DEFAULT_LIMIT));
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
        return IntegerSetting::require(self::KEY . '.limit', $limit, 1);
    }
}
