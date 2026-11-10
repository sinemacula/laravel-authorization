<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Config;

/**
 * Boot-time validator for the `authorization.query_scoping` config
 * (AUTHZ-10.1), run by `ConfigValidator`.
 *
 * The block must be an array, and each limit it sets (`max_anchors`,
 * `max_scopes`, `max_attachments`) a whole number of at least 1, an int or a
 * string written as a whole number, as the environment gives one (N117). A
 * limit it does not set takes its default, and one set to null is refused; any
 * other key is refused, naming its path (N116), so a misspelt limit fails at
 * boot rather than leaving its default in place.
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
        foreach (ConfigBlock::of(self::KEY, $config, self::LIMITS) as $key => $limit) {
            IntegerSetting::require(self::KEY . ".{$key}", $limit, 1);
        }
    }
}
