<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Config;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\IssueCode;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;

/**
 * Validator and reader of the switches of the authorization config: `gate`,
 * `hierarchy` and `rank`, each a block holding one `enabled` setting.
 *
 * A block must be an array setting no key but `enabled`, which must be true or
 * false (N117): anything else, `null`, `0`, `1`, `'0'`, `'false'` or `'off'`
 * among it, is refused rather than read as either, since each switch decides
 * what a check grants. The environment gives a real boolean for `true`,
 * `false`, `(true)` and `(false)`. A block that is left out, or leaves out
 * `enabled`, is on.
 *
 * `isEnabled()` is the one way the package reads the switches at run time, so a
 * value changed after boot is refused there too, never read for its truthiness.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SwitchConfigValidator
{
    /** @var list<string> The blocks that are switches. */
    public const array SWITCHES = ['gate', 'hierarchy', 'rank'];

    /** @var list<string> The keys a switch's block may set. */
    public const array KEYS = ['enabled'];

    /**
     * Validate the switch's block, throwing on the first failure.
     *
     * @param  string  $switch
     * @param  mixed  $config
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function validate(string $switch, mixed $config): void
    {
        $block = ConfigBlock::of("authorization.{$switch}", $config, self::KEYS);

        self::enabled($switch, $block);
    }

    /**
     * Return whether the switch is on, as the configuration holds it now (the
     * given configuration, or the bound one), refusing a block that is not an
     * array and a value that is not a boolean.
     *
     * @param  string  $switch
     * @param  \Illuminate\Contracts\Config\Repository|null  $config
     * @return bool
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function isEnabled(string $switch, ?Repository $config = null): bool
    {
        return self::enabled($switch, ConfigValue::block($switch, $config));
    }

    /**
     * Return the block's `enabled` setting, true when it is left out, refusing
     * one that is not a boolean.
     *
     * @param  string  $switch
     * @param  array<array-key, mixed>  $block
     * @return bool
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function enabled(string $switch, array $block): bool
    {
        $enabled = ConfigBlock::entry($block, 'enabled', true);

        if (\is_bool($enabled)) {
            return $enabled;
        }

        $reason = 'expected true or false, got ' . ConfigValidator::describe($enabled) . '.';

        throw new InvalidAuthorizationConfigException("authorization.{$switch}.enabled", $reason, IssueCode::INVALID_TYPE, 'true or false', \get_debug_type($enabled));
    }
}
