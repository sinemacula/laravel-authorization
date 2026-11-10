<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Config;

use SineMacula\Laravel\Authorization\Evaluation\PolicyLimits;

/**
 * Boot-time validator for the `authorization.policies` config, run by
 * `ConfigValidator`.
 *
 * The block must be an array setting no key but `limits`, itself an array
 * setting no key but the limits a policy document is held to (N116). Each limit
 * it sets must be a whole number of at least 1 (N117); one it leaves out takes
 * its default, and one set to null is refused.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class PolicyConfigValidator
{
    /** @var string The config key of the block. */
    public const string KEY = 'authorization.policies';

    /** @var list<string> The settings the block may set. */
    public const array SETTINGS = ['limits'];

    /**
     * Validate the supplied `policies` config, throwing on the first failure.
     *
     * @param  mixed  $config
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function validate(mixed $config): void
    {
        $block  = ConfigBlock::of(self::KEY, $config, self::SETTINGS);
        $limits = ConfigBlock::of(self::KEY . '.limits', ConfigBlock::entry($block, 'limits', []), PolicyLimits::KEYS);

        foreach ($limits as $key => $limit) {
            IntegerSetting::require(self::KEY . ".limits.{$key}", $limit, 1);
        }
    }
}
