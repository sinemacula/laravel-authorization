<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Diagnostics\Settings;

use SineMacula\Laravel\Authorization\Config\IntegerSetting;

/**
 * Decide whether the report may show a setting's value, and how.
 *
 * A value is shown only when its kind is one the report may show (see
 * `SettingCatalogue`) and the value has the shape the kind expects: a class
 * name, a table's name or prefix, or another name made of the characters such
 * names use, a switch, or a whole number. Anything else, whatever the setting,
 * is shown by its type alone (`string`, `array(3)`), so a credential set where
 * a name was expected is never printed in full.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ValueRenderer
{
    /** @var string A class name, with or without a leading backslash. */
    private const string CLASS_PATTERN = '/\A\\\?[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*(\\\[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*)*\z/';

    /** @var string A plain SQL identifier. */
    private const string TABLE_PATTERN = '/\A[A-Za-z_][A-Za-z0-9_]*\z/';

    /** @var string A plain SQL identifier, or nothing, as the tables' prefix is. */
    private const string TABLE_PREFIX_PATTERN = '/\A(?:[A-Za-z_][A-Za-z0-9_]*)?\z/';

    /** @var string A name, as guards, connections, stores, queues, channels, morph types and permissions are named. */
    private const string NAME_PATTERN = '/\A[A-Za-z0-9_\-:.*]{1,191}\z/';

    /** @var array<string, string> The pattern a value of each kind of one name matches. */
    private const array PATTERNS = [
        SettingCatalogue::CLASS_NAME   => self::CLASS_PATTERN,
        SettingCatalogue::TABLE        => self::TABLE_PATTERN,
        SettingCatalogue::TABLE_PREFIX => self::TABLE_PREFIX_PATTERN,
        SettingCatalogue::NAME         => self::NAME_PATTERN,
    ];

    /** @var array<string, array{string, string|null}> The patterns each entry, and each key when one is given, of a value of each kind of map matches. */
    private const array MAPS = [
        SettingCatalogue::CLASS_LIST => [self::CLASS_PATTERN, null],
        SettingCatalogue::NAME_LIST  => [self::NAME_PATTERN, null],
        SettingCatalogue::CLASS_MAP  => [self::CLASS_PATTERN, self::NAME_PATTERN],
        SettingCatalogue::NAME_MAP   => [self::NAME_PATTERN, self::NAME_PATTERN],
    ];

    /** @var list<string> The kinds whose value may be null, meaning none or the default. */
    private const array NULLABLE = [SettingCatalogue::CLASS_NAME, SettingCatalogue::NAME];

    /**
     * Return the value as the report shows it, wrapped in a list so a value
     * shown as null is told from one not shown, or null when it is not shown.
     *
     * @param  string  $kind
     * @param  mixed  $value
     * @return array{0: mixed}|null
     */
    public static function render(string $kind, mixed $value): ?array
    {
        if (!self::isShown($kind, $value)) {
            return null;
        }

        return [$kind === SettingCatalogue::WHOLE_NUMBER ? IntegerSetting::of($value) : $value];
    }

    /**
     * Return the type of the value as the report shows it: its debug type, with
     * the number of entries of an array.
     *
     * @param  mixed  $value
     * @return string
     */
    public static function typeOf(mixed $value): string
    {
        return \is_array($value) ? 'array(' . \count($value) . ')' : \get_debug_type($value);
    }

    /**
     * Determine whether a value of the kind may be shown: it has the shape the
     * kind expects, and the kind is one the report shows.
     *
     * @param  string  $kind
     * @param  mixed  $value
     * @return bool
     */
    private static function isShown(string $kind, mixed $value): bool
    {
        return match (true) {
            $value === null                          => \in_array($kind, self::NULLABLE, true),
            \array_key_exists($kind, self::PATTERNS) => self::matches(self::PATTERNS[$kind], $value),
            \array_key_exists($kind, self::MAPS)     => self::isMap($value, ...self::MAPS[$kind]),
            $kind === SettingCatalogue::SWITCH       => \is_bool($value),
            $kind === SettingCatalogue::WHOLE_NUMBER => IntegerSetting::of($value) !== null,
            default                                  => false,
        };
    }

    /**
     * Determine whether the value is a string matching the pattern.
     *
     * @param  string  $pattern
     * @param  mixed  $value
     * @return bool
     */
    private static function matches(string $pattern, mixed $value): bool
    {
        return \is_string($value) && \preg_match($pattern, $value) === 1;
    }

    /**
     * Determine whether the value is an array whose every entry matches the
     * pattern, and whose every key matches the key pattern, when one is given.
     *
     * @param  mixed  $value
     * @param  string  $pattern
     * @param  string|null  $keyPattern
     * @return bool
     */
    private static function isMap(mixed $value, string $pattern, ?string $keyPattern): bool
    {
        if (!\is_array($value)) {
            return false;
        }

        foreach ($value as $key => $entry) {
            if (!self::matches($pattern, $entry) || ($keyPattern !== null && !self::matches($keyPattern, (string) $key))) {
                return false;
            }
        }

        return true;
    }
}
