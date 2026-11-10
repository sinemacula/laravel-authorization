<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Config;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authorization\Diagnostics\Enums\IssueCode;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;

/**
 * Boot-time validator for the settings that name an entry of the application's
 * own configuration, run by `ConfigValidator`:
 *
 * - `connection`: the database connection the package's tables live on, a name
 *   under `database.connections`, or null or `''` for the default connection,
 *   in which case `database.default` must name one;
 * - `defaults.guard`: the guard a name is looked up under when none is given, a
 *   name under `auth.guards`, `web` by default; the `defaults` block sets no
 *   other key (N116);
 * - `log_channel`: the channel the package logs to, a name under
 *   `logging.channels`, or null for the default channel;
 * - `usage.connection`: the queue connection grant usage is recorded through,
 *   when set, a name under `queue.connections`.
 *
 * Each is read from the configuration as it stands when the application boots,
 * which a sibling package or the application may have changed while providers
 * registered, and none is connected to, so booting never reaches a database or
 * a queue. Without a configuration repository bound, as in library-mode
 * embedding, only the values' types are checked.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class NamedEntryConfigValidator
{
    /** @var list<string> The settings the `defaults` block may set. */
    public const array DEFAULTS = ['guard'];

    /** @var string The guard `defaults.guard` names when it is not set. */
    public const string GUARD = 'web';

    /**
     * Validate that `connection` names a configured database connection, or
     * selects the default one, which must then be configured.
     *
     * @param  mixed  $value
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function connection(mixed $value, Container $container): void
    {
        if ($value !== null && !\is_string($value)) {
            $reason = 'expected a database connection name, got ' . ConfigValidator::describe($value) . '.';

            $wanted = 'a database connection name or null';

            throw new InvalidAuthorizationConfigException('authorization.connection', $reason, IssueCode::INVALID_TYPE, $wanted, \get_debug_type($value));
        }

        $config = self::config($container);

        if ($config === null) {
            return;
        }

        $isDefault = $value === null || $value === '';
        $name      = $isDefault ? $config->get('database.default') : $value;

        if (self::names($config, 'database.connections', $name)) {
            return;
        }

        $reason = $isDefault
            ? 'the default database connection, database.default, is ' . ConfigValidator::describe($name) . ', which names no entry of database.connections.'
            : "database connection '{$value}' is not configured.";

        $wanted = 'the name of an entry of database.connections';

        throw new InvalidAuthorizationConfigException('authorization.connection', $reason, IssueCode::UNKNOWN_NAME, $wanted, \get_debug_type($value));
    }

    /**
     * Validate the `defaults` block: an array whose `guard`, when set, names a
     * guard under `auth.guards`.
     *
     * @param  mixed  $value
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function defaults(mixed $value, Container $container): void
    {
        self::guard(ConfigBlock::entry(ConfigBlock::of('authorization.defaults', $value, self::DEFAULTS), 'guard', self::GUARD), $container);
    }

    /**
     * Validate that `defaults.guard` names a guard under `auth.guards`.
     *
     * @param  mixed  $value
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function guard(mixed $value, Container $container): void
    {
        self::assertNames('authorization.defaults.guard', $value, 'auth.guards', $container);
    }

    /**
     * Validate that `log_channel` is null, for the default channel, or names a
     * channel under `logging.channels`.
     *
     * @param  mixed  $value
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function logChannel(mixed $value, Container $container): void
    {
        if ($value === null) {
            return;
        }

        self::assertNames('authorization.log_channel', $value, 'logging.channels', $container);
    }

    /**
     * Validate that `usage.connection`, when set, names a connection under
     * `queue.connections`. Its type is checked with the rest of the block.
     *
     * @param  mixed  $value
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    public static function queueConnection(mixed $value, Container $container): void
    {
        if ($value === null) {
            return;
        }

        self::assertNames(UsageConfigValidator::KEY . '.connection', $value, 'queue.connections', $container);
    }

    /**
     * Refuse, under the setting's path, a value that is not a non-empty string
     * naming an entry of the configuration map.
     *
     * @param  string  $path
     * @param  mixed  $value
     * @param  string  $map
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException
     */
    private static function assertNames(string $path, mixed $value, string $map, Container $container): void
    {
        if (!\is_string($value) || $value === '') {
            $reason = 'expected a non-empty name, got ' . ConfigValidator::describe($value) . '.';

            throw new InvalidAuthorizationConfigException($path, $reason, IssueCode::INVALID_TYPE, 'a non-empty name', \get_debug_type($value));
        }

        $config = self::config($container);

        if ($config !== null && !self::names($config, $map, $value)) {
            throw new InvalidAuthorizationConfigException($path, "'{$value}' names no entry of {$map}.", IssueCode::UNKNOWN_NAME, "the name of an entry of {$map}", 'string');
        }
    }

    /**
     * Determine whether the name is a key of the configuration map holding an
     * entry.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  string  $map
     * @param  mixed  $name
     * @return bool
     */
    private static function names(Repository $config, string $map, mixed $name): bool
    {
        $entries = $config->get($map);

        return \is_string($name) && $name !== '' && \is_array($entries) && \is_array($entries[$name] ?? null);
    }

    /**
     * Return the configuration repository bound in the container, or null when
     * none is.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return \Illuminate\Contracts\Config\Repository|null
     */
    private static function config(Container $container): ?Repository
    {
        if (!$container->bound('config')) {
            return null;
        }

        return $container->make('config');
    }
}
