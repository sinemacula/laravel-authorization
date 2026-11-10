<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Container\Container;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\Config\ConfigValidator;
use SineMacula\Laravel\Authorization\Config\NamedEntryConfigValidator;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;
use Tests\Concerns\ReadsRefusedSettings;
use Tests\TestCase;

/**
 * Feature tests for the boot-time validation of the settings that name an entry
 * of the application's own configuration: the database connection, the default
 * guard, the log channel and the queue connection of grant usage, each read
 * from the configuration as it stands when the application boots, and none
 * connected to.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(NamedEntryConfigValidator::class)]
#[CoversClass(ConfigValidator::class)]
final class NamedEntryConfigValidatorTest extends TestCase
{
    use ReadsRefusedSettings;

    /**
     * Null and an empty name select the default connection, which is
     * configured, and a configured connection may be named.
     *
     * @return void
     */
    public function testAConfiguredConnectionIsAccepted(): void
    {
        foreach ([null, '', 'testing'] as $connection) {
            NamedEntryConfigValidator::connection($connection, $this->container());
        }

        $this->expectNotToPerformAssertions();
    }

    /**
     * Return each connection setting refused, with the default connection the
     * application names and why it is refused.
     *
     * @return iterable<string, array{mixed, mixed, string}>
     */
    public static function refusedConnections(): iterable
    {
        $default = static fn (string $described): string => "the default database connection, database.default, is {$described}, which names no entry of database.connections.";

        yield 'a connection not configured' => ['missing', 'testing', 'database connection \'missing\' is not configured.'];
        yield 'a connection that is not a name' => [5, 'testing', 'expected a database connection name, got 5 (int).'];
        yield 'a connection that is an array' => [['testing'], 'testing', 'expected a database connection name, got \'array\' (array).'];
        yield 'null with a default not configured' => [null, 'missing', $default('\'missing\' (string)')];
        yield 'an empty name with a default not configured' => ['', 'missing', $default('\'missing\' (string)')];
        yield 'null with no default' => [null, null, $default('\'null\' (null)')];
        yield 'null with a default that is not a name' => [null, 5, $default('5 (int)')];
    }

    /**
     * A connection that is not a name, names no configured connection, or
     * selects a default the application does not configure is refused.
     *
     * @param  mixed  $connection
     * @param  mixed  $default
     * @param  string  $reason
     * @return void
     */
    #[DataProvider('refusedConnections')]
    public function testAConnectionNotConfiguredIsRefused(mixed $connection, mixed $default, string $reason): void
    {
        $this->config()->set('database.default', $default);

        try {
            $this->assertRefused(fn () => NamedEntryConfigValidator::connection($connection, $this->container()), 'authorization.connection', $reason);
        } finally {
            // The suite's transaction is rolled back on the default connection.
            $this->config()->set('database.default', 'testing');
        }
    }

    /**
     * The connection is checked against the configuration as it stands when the
     * application boots, a connection a provider configured after the package
     * registered included.
     *
     * @return void
     */
    public function testTheConnectionIsCheckedOnTheLiveConfiguration(): void
    {
        $config = $this->authorizationConfig();

        $config['connection'] = 'late';

        $this->assertRefused(fn () => ConfigValidator::validate($config, $this->container()), 'authorization.connection', 'database connection \'late\' is not configured.');

        $this->config()->set('database.connections.late', ['driver' => 'sqlite', 'database' => ':memory:']);

        ConfigValidator::validate($config, $this->container());
    }

    /**
     * The default guard is `web` when left out, and may name any guard under
     * `auth.guards`.
     *
     * @return void
     */
    public function testAConfiguredGuardIsAccepted(): void
    {
        NamedEntryConfigValidator::defaults([], $this->container());
        NamedEntryConfigValidator::defaults(['guard' => 'web'], $this->container());

        $this->config()->set('auth.guards.api', ['driver' => 'token']);

        NamedEntryConfigValidator::defaults(['guard' => 'api'], $this->container());

        self::assertSame(['guard'], NamedEntryConfigValidator::DEFAULTS);
        self::assertSame('web', NamedEntryConfigValidator::GUARD);
    }

    /**
     * Return each `defaults` block refused, with the path and why.
     *
     * @return iterable<string, array{mixed, string, string}>
     */
    public static function refusedDefaults(): iterable
    {
        $guard = 'authorization.defaults.guard';

        yield 'null' => [null, 'authorization.defaults', 'expected an array, got \'null\' (null).'];
        yield 'a string' => ['web', 'authorization.defaults', 'expected an array, got \'web\' (string).'];
        yield 'an unknown key' => [['gaurd' => 'web'], 'authorization.defaults.gaurd', 'unknown key \'gaurd\'; expected one of guard.'];
        yield 'a null guard' => [['guard' => null], $guard, 'expected a non-empty name, got \'null\' (null).'];
        yield 'an empty guard' => [['guard' => ''], $guard, 'expected a non-empty name, got \'\' (string).'];
        yield 'a guard that is not a name' => [['guard' => 5], $guard, 'expected a non-empty name, got 5 (int).'];
        yield 'a guard not configured' => [['guard' => 'admin'], $guard, '\'admin\' names no entry of auth.guards.'];
    }

    /**
     * A `defaults` block that is malformed, or whose guard names no guard under
     * `auth.guards`, is refused.
     *
     * @param  mixed  $defaults
     * @param  string  $path
     * @param  string  $reason
     * @return void
     */
    #[DataProvider('refusedDefaults')]
    public function testAMalformedDefaultsBlockIsRefused(mixed $defaults, string $path, string $reason): void
    {
        $this->assertRefused(fn () => NamedEntryConfigValidator::defaults($defaults, $this->container()), $path, $reason);
    }

    /**
     * Null logs to the default channel, and a channel under `logging.channels`
     * may be named; anything else is refused rather than falling back to the
     * default channel.
     *
     * @return void
     */
    public function testTheLogChannelIsChecked(): void
    {
        $this->config()->set('logging.channels.audit', ['driver' => 'single', 'path' => '/dev/null']);

        NamedEntryConfigValidator::logChannel(null, $this->container());
        NamedEntryConfigValidator::logChannel('audit', $this->container());

        $path = 'authorization.log_channel';

        $this->assertRefused(fn () => NamedEntryConfigValidator::logChannel('missing', $this->container()), $path, '\'missing\' names no entry of logging.channels.');
        $this->assertRefused(fn () => NamedEntryConfigValidator::logChannel('', $this->container()), $path, 'expected a non-empty name, got \'\' (string).');
        $this->assertRefused(fn () => NamedEntryConfigValidator::logChannel(5, $this->container()), $path, 'expected a non-empty name, got 5 (int).');
        $this->assertRefused(fn () => NamedEntryConfigValidator::logChannel(['audit'], $this->container()), $path, 'expected a non-empty name, got \'array\' (array).');
    }

    /**
     * The log channel is checked with the rest of the configuration: a channel
     * under `logging.channels` passes, and one naming none is refused, naming
     * its path, rather than logging to the default channel.
     *
     * @return void
     */
    public function testTheLogChannelIsCheckedWithTheConfiguration(): void
    {
        $this->config()->set('logging.channels.audit', ['driver' => 'single', 'path' => '/dev/null']);

        $config                = $this->authorizationConfig();
        $config['log_channel'] = 'audit';

        ConfigValidator::validate($config, $this->container());

        $config['log_channel'] = 'missing';

        $this->assertRefused(
            fn () => ConfigValidator::validate($config, $this->container()),
            'authorization.log_channel',
            '\'missing\' names no entry of logging.channels.',
        );
    }

    /**
     * The queue connection of grant usage may be null, for the default, or name
     * a connection under `queue.connections`; one naming none is refused with
     * the rest of the configuration, naming its path.
     *
     * @return void
     */
    public function testTheQueueConnectionIsChecked(): void
    {
        $this->config()->set('queue.connections.usage', ['driver' => 'sync']);

        NamedEntryConfigValidator::queueConnection(null, $this->container());
        NamedEntryConfigValidator::queueConnection('usage', $this->container());

        $config          = $this->authorizationConfig();
        $config['usage'] = ['connection' => 'missing'];

        $this->assertRefused(
            fn () => ConfigValidator::validate($config, $this->container()),
            'authorization.usage.connection',
            '\'missing\' names no entry of queue.connections.',
        );
    }

    /**
     * Without a configuration repository bound, as in library-mode embedding,
     * only the values' types are checked.
     *
     * @return void
     */
    public function testWithoutAConfigurationOnlyTypesAreChecked(): void
    {
        $container = new Container;

        NamedEntryConfigValidator::connection('anything', $container);
        NamedEntryConfigValidator::connection(null, $container);
        NamedEntryConfigValidator::defaults(['guard' => 'anything'], $container);
        NamedEntryConfigValidator::logChannel('anything', $container);
        NamedEntryConfigValidator::queueConnection('anything', $container);

        $this->assertRefused(static fn () => NamedEntryConfigValidator::logChannel(5, $container), 'authorization.log_channel', 'expected a non-empty name, got 5 (int).');
    }

    /**
     * The guard is checked on its own, and each refusal of a name is
     * structured, never holding the name.
     *
     * @return void
     */
    public function testEachRefusalIsStructured(): void
    {
        $app = $this->container();

        NamedEntryConfigValidator::guard('web', $app);

        self::assertSame(
            ['authorization.defaults.guard', 'unknown_name', 'the name of an entry of auth.guards', 'string'],
            self::refusedSetting(static fn () => NamedEntryConfigValidator::guard('nowhere', $app)),
        );
        self::assertSame(
            ['authorization.defaults.guard', 'invalid_type', 'a non-empty name', 'int'],
            self::refusedSetting(static fn () => NamedEntryConfigValidator::guard(3, $app)),
        );
        self::assertSame(
            ['authorization.connection', 'invalid_type', 'a database connection name or null', 'array'],
            self::refusedSetting(static fn () => NamedEntryConfigValidator::connection([], $app)),
        );
        self::assertSame(
            ['authorization.connection', 'unknown_name', 'the name of an entry of database.connections', 'string'],
            self::refusedSetting(static fn () => NamedEntryConfigValidator::connection('nowhere', $app)),
        );
    }

    /**
     * Return the application's configuration repository.
     *
     * @return \Illuminate\Contracts\Config\Repository
     */
    private function config(): ConfigRepository
    {
        return $this->container()->make(ConfigRepository::class);
    }

    /**
     * Assert the callback is refused with the given config key and reason.
     *
     * @param  callable(): mixed  $callback
     * @param  string  $key
     * @param  string  $reason
     * @return void
     */
    private function assertRefused(callable $callback, string $key, string $reason): void
    {
        try {
            $callback();

            self::fail('InvalidAuthorizationConfigException was not thrown.');
        } catch (InvalidAuthorizationConfigException $exception) {
            self::assertSame($key, $exception->getConfigKey());
            self::assertSame($reason, $exception->getReason());
        }
    }
}
