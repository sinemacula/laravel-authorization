<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Config;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\IssueCode;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;
use SineMacula\Laravel\Authorization\Models\Role;

/**
 * Boot-time validator and reader of the `authorization.break_glass` config
 * (AUTHZ-11.7, N133), run by `ConfigValidator`.
 *
 * The block must be an array of these settings, each optional:
 *
 * - `enabled`: whether break-glass is on, a boolean, false by default. True is
 *   refused while `AVAILABLE` is false: break-glass is not available until its
 *   audit trail ships, and that release flips the constant;
 * - `max_minutes`: the longest an activation may last, in minutes, a whole
 *   number of at least 1, 60 by default;
 * - `roles`: the emergency roles, each role's name mapped to its settings, an
 *   array setting only `max_minutes`: a whole number from 1 up to the global
 *   maximum, or null, or left out, for the global maximum. A name must be a
 *   valid role name (see `ValidatesAuthorizationName`); whether a role of that
 *   name exists is checked when it is activated, never at boot, which reads no
 *   database;
 * - `justifications`: the codes an activation gives one of, a list of distinct
 *   codes, each a lower-case letter, then lower-case letters, digits, `.`, `_`
 *   and `-`, of at most `CODE_LENGTH` characters; the list must not be empty
 *   while break-glass is enabled;
 * - `notes`: whether an activation may carry a free-text note, a boolean, false
 *   by default;
 * - `note_max_length`: the most characters a note may have, a whole number of
 *   at least 1, 500 by default.
 *
 * Whole numbers are ints or strings written as whole numbers, as the
 * environment gives them, and switches real booleans (N117). A setting set to
 * null is refused, but for a role's `max_minutes`. Any other key, in the block
 * or a role's settings, is refused, naming its path (N116). The same checks
 * refuse a setting changed after boot when it is read (see `read()`).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class BreakGlassConfigValidator
{
    /** @var string The config key of the block. */
    public const string KEY = 'authorization.break_glass';

    /** @var bool Whether break-glass may be enabled: false until its audit trail ships, which flips it. */
    public const bool AVAILABLE = false;

    /** @var list<string> The settings the block may set. */
    public const array SETTINGS = ['enabled', 'max_minutes', 'roles', 'justifications', 'notes', 'note_max_length'];

    /** @var list<string> The settings a role's entry may set. */
    public const array ROLE_SETTINGS = ['max_minutes'];

    /** @var int The longest an activation may last by default, in minutes. */
    public const int MAX_MINUTES = 60;

    /** @var int The most characters a note may have by default. */
    public const int NOTE_MAX_LENGTH = 500;

    /** @var int The most characters a justification code may have. */
    public const int CODE_LENGTH = 64;

    /** @var string Why `enabled` true is refused while break-glass is not available. */
    public const string UNAVAILABLE = 'break-glass is not available until its audit trail ships; leave it disabled.';

    /** @var string A justification code: a lower-case letter, then lower-case letters, digits, dots, underscores and hyphens. */
    private const string CODE = '/\A[a-z][a-z0-9._-]*\z/';

    /** @var string What a justification code is expected to be. */
    private const string CODE_SHAPE = 'a lower-case letter, then lower-case letters, digits, ".", "_" and "-", of at most 64 characters';

    /**
     * Validate the supplied `break_glass` config, throwing on the first
     * failure.
     *
     * @param  mixed  $config
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function validate(mixed $config): void
    {
        self::settings($config);
    }

    /**
     * Return the settings the configuration sets, read through the same checks
     * the boot runs, so a setting changed after boot is refused when it is
     * read, never read as its default.
     *
     * @param  \Illuminate\Contracts\Config\Repository|null  $config
     * @return array{enabled: bool, max_minutes: int, roles: array<string, int>, justifications: list<string>, notes: bool, note_max_length: int}
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function read(?Repository $config = null): array
    {
        return self::settings(ConfigValue::block('break_glass', $config));
    }

    /**
     * Return the settings of the block given, each checked, with the defaults
     * of those it leaves out, and every role's maximum resolved.
     *
     * @param  mixed  $config
     * @return array{enabled: bool, max_minutes: int, roles: array<string, int>, justifications: list<string>, notes: bool, note_max_length: int}
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function settings(mixed $config): array
    {
        $block   = ConfigBlock::of(self::KEY, $config, self::SETTINGS);
        $enabled = self::enabled(ConfigBlock::entry($block, 'enabled', false));
        $maximum = self::maxMinutes(ConfigBlock::entry($block, 'max_minutes', self::MAX_MINUTES));

        return [
            'enabled'         => $enabled,
            'max_minutes'     => $maximum,
            'roles'           => self::roles(ConfigBlock::entry($block, 'roles', []), $maximum),
            'justifications'  => self::justifications(ConfigBlock::entry($block, 'justifications', []), $enabled),
            'notes'           => self::notes(ConfigBlock::entry($block, 'notes', false)),
            'note_max_length' => self::noteMaxLength(ConfigBlock::entry($block, 'note_max_length', self::NOTE_MAX_LENGTH)),
        ];
    }

    /**
     * Return whether break-glass is enabled, refusing a value that is not a
     * boolean, and true while break-glass is not available.
     *
     * @param  mixed  $enabled
     * @param  bool  $isAvailable
     * @return bool
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function enabled(mixed $enabled, bool $isAvailable = self::AVAILABLE): bool
    {
        $enabled = self::isSwitchedOn('enabled', $enabled);

        if ($enabled && !$isAvailable) {
            throw new InvalidAuthorizationConfigException(self::KEY . '.enabled', self::UNAVAILABLE, IssueCode::INVALID_VALUE, 'false', 'bool');
        }

        return $enabled;
    }

    /**
     * Return the longest an activation may last, in minutes, refusing anything
     * but a whole number of at least 1.
     *
     * @param  mixed  $minutes
     * @return int
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function maxMinutes(mixed $minutes): int
    {
        return IntegerSetting::require(self::KEY . '.max_minutes', $minutes, 1);
    }

    /**
     * Return the longest an activation of each emergency role may last, in
     * minutes, by the role's name, refusing a value that is not an array, and
     * an entry `role()` refuses.
     *
     * @param  mixed  $roles
     * @param  int  $maximum
     * @return array<string, int>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function roles(mixed $roles, int $maximum): array
    {
        $limits = [];

        foreach (ConfigBlock::entries(self::KEY . '.roles', $roles, 'an array of role names mapped to their settings', static fn (): null => null) as $name => $settings) {
            $limit         = self::role($name, $settings, $maximum);
            $limits[$name] = $limit;
        }

        return $limits;
    }

    /**
     * Return the longest an activation of the emergency role may last, in
     * minutes: its own maximum, or the global one when it sets none. A name
     * that is not a valid role name, settings that are not an array or set a
     * key but `max_minutes`, and a maximum that is not a whole number from 1 up
     * to the global one, are refused.
     *
     * @param  int|string  $name
     * @param  mixed  $settings
     * @param  int  $maximum
     * @return int
     *
     * @phpstan-assert string $name
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function role(int|string $name, mixed $settings, int $maximum): int
    {
        $path = self::KEY . ".roles.{$name}";

        if (!\is_string($name) || !Role::isValidAuthorizationName($name)) {
            $reason = 'expected a role name (letters, digits, "_", "-", ":", "." and "*", of at most 191 characters), got ' . ConfigValidator::describe($name) . '.';

            throw new InvalidAuthorizationConfigException($path, $reason, IssueCode::INVALID_VALUE, 'a role name mapped to its settings', \get_debug_type($name));
        }

        $minutes = ConfigBlock::entry(ConfigBlock::of($path, $settings, self::ROLE_SETTINGS), 'max_minutes', null);
        $limit   = $minutes === null ? $maximum : IntegerSetting::require("{$path}.max_minutes", $minutes, 1);

        if ($limit > $maximum) {
            $reason = "a role's maximum of {$limit} minutes is longer than the global maximum of {$maximum}.";

            $expected = "a whole number from 1 to {$maximum}, or null";

            throw new InvalidAuthorizationConfigException("{$path}.max_minutes", $reason, IssueCode::OUT_OF_RANGE, $expected, \get_debug_type($minutes));
        }

        return $limit;
    }

    /**
     * Return the justification codes, refusing a value that is not a list, a
     * code `justification()` refuses, a code listed twice, and an empty list
     * while break-glass is enabled.
     *
     * @param  mixed  $codes
     * @param  bool  $enabled
     * @return list<string>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function justifications(mixed $codes, bool $enabled): array
    {
        $path = self::KEY . '.justifications';

        if (!\is_array($codes) || !\array_is_list($codes)) {
            $reason = 'expected a list of justification codes, got ' . \get_debug_type($codes) . '.';

            throw new InvalidAuthorizationConfigException($path, $reason, IssueCode::INVALID_TYPE, 'a list of justification codes', \get_debug_type($codes));
        }

        if ($enabled && $codes === []) {
            $reason = 'break-glass is enabled, so at least one justification code must be listed.';

            throw new InvalidAuthorizationConfigException($path, $reason, IssueCode::INVALID_VALUE, 'a list of at least one code', 'array');
        }

        $listed = [];

        foreach ($codes as $index => $code) {
            $listed[self::justification($index, $code, $listed)] = $index;
        }

        return \array_keys($listed);
    }

    /**
     * Return the justification code at the index, refusing one that is not a
     * code, or that the codes before it already list.
     *
     * @param  int  $index
     * @param  mixed  $code
     * @param  array<string, int>  $listed
     * @return string
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function justification(int $index, mixed $code, array $listed = []): string
    {
        $path = self::KEY . ".justifications.{$index}";

        if (!\is_string($code)) {
            $reason = 'expected a justification code, got ' . ConfigValidator::describe($code) . '.';

            throw new InvalidAuthorizationConfigException($path, $reason, IssueCode::INVALID_TYPE, self::CODE_SHAPE, \get_debug_type($code));
        }

        [$issue, $reason] = match (true) {
            \preg_match(self::CODE, $code) !== 1 => [IssueCode::INVALID_VALUE, "code '{$code}' is not " . self::CODE_SHAPE . '.'],
            \strlen($code) > self::CODE_LENGTH   => [IssueCode::OUT_OF_RANGE, "code '{$code}' is longer than " . self::CODE_LENGTH . ' characters.'],
            isset($listed[$code])                => [IssueCode::DUPLICATE, "code '{$code}' is already listed at index {$listed[$code]}."],
            default                              => [null, ''],
        };

        return $issue === null ? $code : throw new InvalidAuthorizationConfigException($path, $reason, $issue, self::CODE_SHAPE, 'string');
    }

    /**
     * Return whether an activation may carry a free-text note, refusing a value
     * that is not a boolean.
     *
     * @param  mixed  $notes
     * @return bool
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function notes(mixed $notes): bool
    {
        return self::isSwitchedOn('notes', $notes);
    }

    /**
     * Return the most characters a note may have, refusing anything but a whole
     * number of at least 1.
     *
     * @param  mixed  $length
     * @return int
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function noteMaxLength(mixed $length): int
    {
        return IntegerSetting::require(self::KEY . '.note_max_length', $length, 1);
    }

    /**
     * Determine whether the switch under the setting is on, refusing a value
     * that is not a boolean.
     *
     * @param  string  $setting
     * @param  mixed  $value
     * @return bool
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    private static function isSwitchedOn(string $setting, mixed $value): bool
    {
        if (\is_bool($value)) {
            return $value;
        }

        $reason = 'expected true or false, got ' . ConfigValidator::describe($value) . '.';

        throw new InvalidAuthorizationConfigException(self::KEY . ".{$setting}", $reason, IssueCode::INVALID_TYPE, 'true or false', \get_debug_type($value));
    }
}
