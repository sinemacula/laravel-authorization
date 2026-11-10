<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Config;

use SineMacula\Laravel\Authorization\Diagnostics\Enums\IssueCode;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;

/**
 * Read a whole-number setting as it is written (N117).
 *
 * The config file reads each whole-number setting from the environment without
 * a cast, so a malformed value is refused rather than quietly read as another
 * number. A setting holds a PHP int, taken as it is, or a string that is a
 * whole number written in base 10 the plain way, as the environment gives
 * `'300'`: an optional minus sign, then `0` alone or digits that do not start
 * with `0`, with nothing before or after them, and no larger than PHP holds.
 * Anything else, `'12abc'`, `'1e3'`, `' 5'`, `'5.0'`, `'-0'`, `''`, a float or
 * a boolean among it, is not a whole number.
 *
 * The boot validators and the readers of the settings both read them through
 * here, so a value is never read one way at boot and another at run time.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class IntegerSetting
{
    /** @var string A whole number other than 0, written in base 10 the plain way. */
    private const string PATTERN = '/\A-?[1-9][0-9]*\z/';

    /**
     * Return the whole number the value holds, or null when it holds none.
     *
     * @param  mixed  $value
     * @return int|null
     */
    public static function of(mixed $value): ?int
    {
        if (\is_int($value)) {
            return $value;
        }

        if (!\is_string($value) || ($value !== '0' && \preg_match(self::PATTERN, $value) !== 1)) {
            return null;
        }

        // A number too large for PHP reads as the largest one it holds, which
        // does not read back as the number written.
        $integer = (int) $value;

        return (string) $integer === $value ? $integer : null;
    }

    /**
     * Return the whole number the setting holds, refusing, under its path, a
     * value that holds none or holds one below the least allowed.
     *
     * @param  string  $path
     * @param  mixed  $value
     * @param  int  $least
     * @param  string  $expected
     * @return int
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function require(string $path, mixed $value, int $least, string $expected = 'a whole number'): int
    {
        $integer = self::of($value);

        if ($integer !== null && $integer >= $least) {
            return $integer;
        }

        $issue = $integer === null ? IssueCode::INVALID_TYPE : IssueCode::OUT_OF_RANGE;

        $reason = "expected {$expected} of at least {$least}, got " . ConfigValidator::describe($value) . '.';

        throw new InvalidAuthorizationConfigException($path, $reason, $issue, "{$expected} of at least {$least}", \get_debug_type($value));
    }
}
