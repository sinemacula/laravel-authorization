<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Config;

use SineMacula\Laravel\Authorization\Contracts\GrantHook;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;

/**
 * Boot-time validator for the `authorization.grant_hooks` config (AUTHZ-11.3),
 * run by `ConfigValidator`.
 *
 * The value must be a list of class names, in the order the hooks run, each an
 * existing class implementing `GrantHook`, and each listed once, whatever the
 * case of its name and with or without a leading backslash: a hook listed twice
 * would run twice for one grant. An empty list, the default, binds a composite
 * that does nothing. Keys other than a list's are refused, so a map whose order
 * a reader might misjudge fails at boot.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class GrantHookConfigValidator
{
    /** @var string The config key of the list. */
    public const string KEY = 'authorization.grant_hooks';

    /**
     * Validate the supplied `grant_hooks` config, throwing on the first
     * failure, and return the classes it lists. The listed hooks are read
     * through here at run time too, before any is built, so a value changed
     * after boot is refused there, never cast.
     *
     * @param  mixed  $config
     * @return list<class-string<\SineMacula\Laravel\Authorization\Contracts\GrantHook>>
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function validate(mixed $config): array
    {
        if (!\is_array($config) || !\array_is_list($config)) {
            throw new InvalidAuthorizationConfigException(self::KEY, 'expected a list of class names, got ' . \get_debug_type($config) . '.');
        }

        $seen = [];

        foreach ($config as $index => $class) {
            ImplementationConfigValidator::validate(self::KEY . ".{$index}", $class, GrantHook::class, 'expected a class-string, got null.');

            // PHP names one class whatever the case, with or without a leading
            // backslash, so a duplicate is told by its normalised name.
            $name = \strtolower(\ltrim($class, '\\'));

            if (isset($seen[$name])) {
                throw new InvalidAuthorizationConfigException(self::KEY . ".{$index}", "class '{$class}' is listed more than once.");
            }

            $seen[$name] = true;
        }

        /** @var list<class-string<\SineMacula\Laravel\Authorization\Contracts\GrantHook>> */
        return $config;
    }
}
