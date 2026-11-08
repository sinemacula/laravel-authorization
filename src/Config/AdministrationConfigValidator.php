<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Config;

use SineMacula\Laravel\Authorization\Administration\AffectedHolders;
use SineMacula\Laravel\Authorization\Administration\ConflictRetries;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;

/**
 * Boot-time validator for the `authorization.administration` config
 * (AUTHZ-11.1), run by `ConfigValidator`.
 *
 * The block must be an array, and each limit it may set a whole number:
 * `max_impact`, the most holders a delegated change to a shared definition is
 * weighed against (see `Administration\Impact`), of at least 1, and `retries`,
 * how many times a delegated call that conflicts is tried again (see
 * `Administration\ConflictRetries`), of at least 0. A limit it does not set
 * takes its default; any other key is refused, so a misspelt limit fails at
 * boot rather than leaving its default in place.
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
        if (!\is_array($config)) {
            throw new InvalidAuthorizationConfigException(self::KEY, 'expected an array of limits, got ' . self::describe($config) . '.');
        }

        $unknown = \array_values(\array_diff(\array_keys($config), self::LIMITS));

        if ($unknown !== []) {
            throw new InvalidAuthorizationConfigException(self::KEY, "unknown limit '{$unknown[0]}'; expected one of " . \implode(', ', self::LIMITS) . '.');
        }

        self::assertWhole('max_impact', $config['max_impact'] ?? AffectedHolders::DEFAULT_LIMIT, 1);
        self::assertWhole('retries', $config['retries'] ?? ConflictRetries::DEFAULT_RETRIES, 0);
    }

    /**
     * Refuse a limit that is not a whole number of at least the minimum, under
     * its key.
     *
     * @param  string  $key
     * @param  mixed  $limit
     * @param  int  $minimum
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    private static function assertWhole(string $key, mixed $limit, int $minimum): void
    {
        if (\is_int($limit) && $limit >= $minimum) {
            return;
        }

        throw new InvalidAuthorizationConfigException(self::KEY . ".{$key}", "expected a whole number of at least {$minimum}, got " . self::describe($limit) . '.');
    }

    /**
     * Describe a value for a message: a scalar as its literal, anything else by
     * its type, each followed by its type.
     *
     * @param  mixed  $value
     * @return string
     */
    private static function describe(mixed $value): string
    {
        return \var_export(\is_scalar($value) ? $value : \get_debug_type($value), true) . ' (' . \get_debug_type($value) . ')';
    }
}
