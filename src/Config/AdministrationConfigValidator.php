<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Config;

use SineMacula\Laravel\Authorization\Administration\AffectedHolders;
use SineMacula\Laravel\Authorization\Administration\ConflictRetries;

/**
 * Boot-time validator for the `authorization.administration` config
 * (AUTHZ-11.1), run by `ConfigValidator`.
 *
 * The block must be an array, and each limit it may set a whole number:
 * `max_impact`, the most holders a delegated change to a shared definition is
 * weighed against (see `Administration\Impact`), of at least 1, and `retries`,
 * how many times a delegated call that conflicts is tried again (see
 * `Administration\ConflictRetries`), of at least 0, each an int or a string
 * written as a whole number, as the environment gives one (N117). A limit it
 * does not set takes its default, and one set to null is refused; any other key
 * is refused, naming its path (N116), so a misspelt limit fails at boot rather
 * than leaving its default in place.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class AdministrationConfigValidator
{
    /** @var string The config key of the block. */
    public const string KEY = 'authorization.administration';

    /** @var list<string> The limits the block may set. */
    public const array LIMITS = ['max_impact', 'retries'];

    /**
     * Validate the supplied `administration` config, throwing on the first
     * failure.
     *
     * @param  mixed  $config
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function validate(mixed $config): void
    {
        $block = ConfigBlock::of(self::KEY, $config, self::LIMITS);

        IntegerSetting::require(self::KEY . '.max_impact', ConfigBlock::entry($block, 'max_impact', AffectedHolders::DEFAULT_LIMIT), 1);
        IntegerSetting::require(self::KEY . '.retries', ConfigBlock::entry($block, 'retries', ConflictRetries::DEFAULT_RETRIES), 0);
    }
}
