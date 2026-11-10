<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Config\Repository;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\Administration\AffectedHolders;
use SineMacula\Laravel\Authorization\Administration\ConflictRetries;
use SineMacula\Laravel\Authorization\Config\ConfigValue;
use SineMacula\Laravel\Authorization\Config\DefaultGuard;
use SineMacula\Laravel\Authorization\Config\ModelClasses;
use SineMacula\Laravel\Authorization\Config\TableNames;
use SineMacula\Laravel\Authorization\Context\AttributeProviders;
use SineMacula\Laravel\Authorization\Context\ContextBindings;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Enums\GrantTarget;
use SineMacula\Laravel\Authorization\Evaluation\CheckBatch;
use SineMacula\Laravel\Authorization\Evaluation\PolicyLimits;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;
use SineMacula\Laravel\Authorization\Hooks\GrantHooks;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Query\QueryAuthorizer;
use SineMacula\Laravel\Authorization\Query\ScopeClasses;
use SineMacula\Laravel\Authorization\Registrars\GateRegistrar;
use SineMacula\Laravel\Authorization\Reviews\ReviewQuery;
use SineMacula\Laravel\Authorization\Services\ApplicationAccess;
use SineMacula\Laravel\Authorization\Support\PermissionCatalogue;
use SineMacula\Laravel\Authorization\Support\SessionScopes;
use SineMacula\Laravel\Authorization\Usage\UsageTracking;
use Tests\TestCase;

/**
 * Feature tests for reading the authorization config at run time: a setting
 * left out takes its default, and a setting, or a block holding it, changed
 * after boot to a value boot would refuse is refused by every reader with
 * `InvalidAuthorizationConfigException`, naming its path, never read as its
 * default, cast or skipped.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(ConfigValue::class)]
#[CoversClass(TableNames::class)]
#[CoversClass(ModelClasses::class)]
#[CoversClass(DefaultGuard::class)]
#[CoversClass(PolicyLimits::class)]
#[CoversClass(ScopeClasses::class)]
#[CoversClass(QueryAuthorizer::class)]
#[CoversClass(CheckBatch::class)]
#[CoversClass(AffectedHolders::class)]
#[CoversClass(ConflictRetries::class)]
#[CoversClass(GateRegistrar::class)]
#[CoversClass(PermissionCatalogue::class)]
#[CoversClass(ApplicationAccess::class)]
#[CoversClass(SessionScopes::class)]
#[CoversClass(ContextBindings::class)]
#[CoversClass(AttributeProviders::class)]
#[CoversClass(GrantHooks::class)]
#[CoversClass(AuthorizationConnection::class)]
#[CoversClass(UsageTracking::class)]
#[CoversClass(ReviewQuery::class)]
final class ConfigValueTest extends TestCase
{
    /**
     * A setting is read as the configuration holds it, null included, and one
     * the configuration leaves out takes the default.
     *
     * @return void
     */
    public function testASettingIsReadOrTakesItsDefault(): void
    {
        $this->config()->set('authorization.cache', ['ttl' => 60, 'store' => null]);

        self::assertSame(60, ConfigValue::get('cache.ttl', 300));
        self::assertNull(ConfigValue::get('cache.store', 'array'));
        self::assertSame('authorization', ConfigValue::get('cache.prefix', 'authorization'));
        self::assertSame('none', ConfigValue::get('missing.setting', 'none'));
        self::assertSame(['ttl' => 60, 'store' => null], ConfigValue::block('cache'));
        self::assertSame([], ConfigValue::block('missing'));
    }

    /**
     * A configuration given to the read is read in place of the bound one, and
     * one without the authorization config gives every default.
     *
     * @return void
     */
    public function testAGivenConfigurationIsRead(): void
    {
        $config = new Repository(['authorization' => ['gate' => ['enabled' => false]]]);

        self::assertFalse(ConfigValue::get('gate.enabled', true, $config));
        self::assertSame('default', ConfigValue::get('gate.enabled', 'default', new Repository));
    }

    /**
     * A container whose `config` binding is not a configuration repository
     * gives every default, as one with none bound does.
     *
     * @return void
     */
    public function testABindingThatIsNotAConfigurationGivesEveryDefault(): void
    {
        $original = $this->container()->make('config');

        $this->container()->instance('config', new \stdClass);

        try {
            self::assertSame('default', ConfigValue::get('gate.enabled', 'default'));
        } finally {
            $this->container()->instance('config', $original);
        }
    }

    /**
     * A name is read as the configuration holds it, takes its default when left
     * out, and is refused, with what was expected, when it is not a non-empty
     * string.
     *
     * @return void
     */
    public function testANameIsReadOrRefused(): void
    {
        $this->config()->set('authorization.defaults', ['guard' => 'api']);

        self::assertSame('api', ConfigValue::name('defaults.guard', 'web', 'a guard'));
        self::assertSame('none', ConfigValue::name('defaults.missing', 'none', 'a guard'));

        foreach (['\'\'' => '', '5' => 5, '\'null\'' => null] as $described => $value) {
            $this->config()->set('authorization.defaults.guard', $value);

            $reason = "expected a guard, got {$described} (" . \get_debug_type($value) . ').';

            $this->assertRefused(static fn () => ConfigValue::name('defaults.guard', 'web', 'a guard'), 'authorization.defaults.guard', $reason);
        }
    }

    /**
     * The tables, models and default guard are read as configured, and each, or
     * its block, changed after boot to a value that cannot name a table, a
     * class or a guard is refused when it is read, before any query, never read
     * as the package's default.
     *
     * @return void
     */
    public function testTheTableModelAndGuardReadersRefuseAValueChangedAfterBoot(): void
    {
        $this->config()->set('authorization.tables.roles', 'authz_roles');

        self::assertSame('authz_roles', (new Role)->getTable());

        $this->config()->set('authorization.tables.roles', 5);

        $this->assertRefused(static fn () => new Role, 'authorization.tables.roles', 'expected a table name, got 5 (int).');

        $this->config()->set('authorization.tables', null);

        $this->assertRefused(static fn () => GrantTarget::ROLE->table(), 'authorization.tables', 'expected an array, got \'null\' (null).');

        $this->config()->set('authorization.models', ['role' => null]);

        $this->assertRefused(static fn () => GrantTarget::ROLE->named('editor', 'web'), 'authorization.models.role', 'expected a class-string, got \'null\' (null).');

        $this->config()->set('authorization.models', []);
        $this->config()->set('authorization.defaults', ['guard' => '']);

        $this->assertRefused(static fn () => GrantTarget::ROLE->named('editor', null), 'authorization.defaults.guard', 'expected a non-empty name, got \'\' (string).');
    }

    /**
     * A block on the way to a setting that is not an array, the config itself
     * among them, is refused under its own path, never read as a block that
     * leaves the setting out.
     *
     * @return void
     */
    public function testABlockThatIsNotAnArrayIsRefused(): void
    {
        $this->config()->set('authorization.cache', 'redis');

        $this->assertRefused(static fn () => ConfigValue::get('cache.ttl', 300), 'authorization.cache', 'expected an array, got \'redis\' (string).');

        $this->config()->set('authorization.cache', ['ttl' => 'soon']);

        $this->assertRefused(static fn () => ConfigValue::block('cache.ttl'), 'authorization.cache.ttl', 'expected an array, got \'soon\' (string).');

        $this->config()->set('authorization', null);

        $this->assertRefused(static fn () => ConfigValue::get('cache.ttl', 300), 'authorization', 'expected an array, got \'null\' (null).');
    }

    /**
     * A whole-number setting is read as an int or as the environment writes
     * one, takes its default when left out, and is refused when it is not a
     * whole number of at least the least allowed.
     *
     * @return void
     */
    public function testAWholeNumberSettingIsReadOrRefused(): void
    {
        self::assertSame(7, ConfigValue::integer('missing.limit', 7, 1));

        $this->config()->set('authorization.bulk.chunk_size', '250');

        self::assertSame(250, ConfigValue::integer('bulk.chunk_size', 500, 1));

        $read = static fn (): int => ConfigValue::integer('bulk.chunk_size', 500, 1);

        $this->config()->set('authorization.bulk.chunk_size', 0);

        $this->assertRefused($read, 'authorization.bulk.chunk_size', 'expected a whole number of at least 1, got 0 (int).');

        $this->config()->set('authorization.bulk.chunk_size', '12abc');

        $this->assertRefused($read, 'authorization.bulk.chunk_size', 'expected a whole number of at least 1, got \'12abc\' (string).');
    }

    /**
     * Return each whole-number reader, with the setting it reads.
     *
     * @return iterable<string, array{string, callable(): mixed}>
     */
    public static function wholeNumberReaders(): iterable
    {
        yield 'a policy limit' => ['policies.limits.statements', static fn (): mixed => PolicyLimits::fromConfig()->statements];
        yield 'the most scopes' => ['query_scoping.max_scopes', static fn (): mixed => (new \ReflectionMethod(ScopeClasses::class, 'limit'))->invoke(null, 'max_scopes', 32)];
        yield 'the most anchors' => ['query_scoping.max_anchors', static fn (): mixed => (new \ReflectionMethod(ScopeClasses::class, 'limit'))->invoke(null, 'max_anchors', 8)];
        yield 'the most attachments' => ['query_scoping.max_attachments', static fn (): mixed => (new \ReflectionMethod(QueryAuthorizer::class, 'attachmentLimit'))->invoke(null)];
        yield 'the chunk size' => ['bulk.chunk_size', static fn (): mixed => (new \ReflectionMethod(CheckBatch::class, 'chunkSize'))->invoke(null)];
        yield 'the most impact' => ['administration.max_impact', static fn (): mixed => AffectedHolders::limit()];
        yield 'the review limit' => ['reviews.limit', static fn (): mixed => ReviewQuery::defaultLimit()];
    }

    /**
     * Each whole-number reader refuses a setting changed after boot to one that
     * is not a whole number, is below its least or is null, never reading it as
     * its default, and reads its least, 1, as it is.
     *
     * @param  string  $setting
     * @param  callable(): mixed  $reader
     * @return void
     */
    #[DataProvider('wholeNumberReaders')]
    public function testAWholeNumberReaderRefusesAValueChangedAfterBoot(string $setting, callable $reader): void
    {
        foreach (['ten', '1e3', '5.0', 0, -1, 1.5, true, null] as $value) {
            $this->config()->set("authorization.{$setting}", $value);

            $this->assertRefused($reader, "authorization.{$setting}");
        }

        $this->config()->set("authorization.{$setting}", '40');

        $reader();

        $this->config()->set("authorization.{$setting}", '1');

        self::assertSame(1, $reader());
    }

    /**
     * The retries may be 0, as the environment writes it too, and are refused
     * below that or when they are not a whole number.
     *
     * @return void
     */
    public function testTheRetriesReaderRefusesAValueChangedAfterBoot(): void
    {
        $this->config()->set('authorization.administration.retries', '0');

        self::assertSame(0, ConflictRetries::retries());

        foreach (['-1', -1, 'two', null, 2.0] as $value) {
            $this->config()->set('authorization.administration.retries', $value);

            $this->assertRefused(static fn () => ConflictRetries::retries(), 'authorization.administration.retries');
        }
    }

    /**
     * The policy limits refuse a block of limits, or the `policies` block,
     * changed after boot to something that is not an array.
     *
     * @return void
     */
    public function testThePolicyLimitsRefuseABlockThatIsNotAnArray(): void
    {
        $this->config()->set('authorization.policies.limits', 'none');

        $this->assertRefused(static fn () => PolicyLimits::fromConfig(), 'authorization.policies.limits', 'expected an array, got \'none\' (string).');

        $this->config()->set('authorization.policies', null);

        $this->assertRefused(static fn () => PolicyLimits::fromConfig(), 'authorization.policies', 'expected an array, got \'null\' (null).');
    }

    /**
     * The Gate switch is read strictly: true or left out turns the hook on,
     * false turns it off, and anything else is refused rather than read as on.
     *
     * @return void
     */
    public function testTheGateSwitchRefusesAValueChangedAfterBoot(): void
    {
        $config = $this->config();

        foreach (['false', 0, 'off', null] as $value) {
            $config->set('authorization.gate.enabled', $value);

            $this->assertRefused(static fn () => GateRegistrar::isEnabled($config), 'authorization.gate.enabled');
        }

        $config->set('authorization.gate', 'on');

        $this->assertRefused(static fn () => GateRegistrar::isEnabled($config), 'authorization.gate', 'expected an array, got \'on\' (string).');
    }

    /**
     * The permission catalogue refuses an entry of `permission_enums` or
     * `permission_providers` changed after boot to one boot would refuse,
     * before it reads or resolves any, rather than skipping it.
     *
     * @return void
     */
    public function testThePermissionCatalogueRefusesAListChangedAfterBoot(): void
    {
        $catalogue = $this->container()->make(PermissionCatalogue::class);

        $this->config()->set('authorization.permission_enums', [\stdClass::class]);

        $this->assertRefused(static fn () => $catalogue->definitions(), 'authorization.permission_enums.0');

        $this->config()->set('authorization.permission_enums', 'none');

        $this->assertRefused(static fn () => $catalogue->definitions(), 'authorization.permission_enums');

        $this->config()->set('authorization.permission_enums', []);
        $this->config()->set('authorization.permission_providers', ['Missing\Provider']);

        $this->assertRefused(static fn () => $catalogue->definitions(), 'authorization.permission_providers.0', 'class \'Missing\Provider\' does not exist.');

        $this->config()->set('authorization.permission_providers', [\stdClass::class]);

        $this->assertRefused(static fn () => $catalogue->definitions(), 'authorization.permission_providers.0');
    }

    /**
     * Application access refuses an entry for the application, or a map,
     * changed after boot to one that names no permission, null among it, rather
     * than opening the application to every principal; an application the map
     * does not name stays open.
     *
     * @return void
     */
    public function testApplicationAccessRefusesAnEntryChangedAfterBoot(): void
    {
        $access = new ApplicationAccess;

        $this->config()->set('authorization.application_access', ['admin' => 'admin:access']);

        self::assertTrue($access->mayUse('portal', new \stdClass, null));

        $refused = [
            'expected a non-empty permission name, got \'null\' (null).'   => null,
            'expected a non-empty permission name, got \'\' (string).'     => '',
            'expected a non-empty permission name, got 5 (int).'           => 5,
            'expected a non-empty permission name, got \'array\' (array).' => ['admin:access'],
        ];

        foreach ($refused as $reason => $value) {
            $this->config()->set('authorization.application_access', ['admin' => $value]);

            $this->assertRefused(static fn () => $access->mayUse('admin', new \stdClass, null), 'authorization.application_access.admin', $reason);
        }

        $this->config()->set('authorization.application_access', null);

        $this->assertRefused(static fn () => $access->mayUse('portal', new \stdClass, null), 'authorization.application_access', 'expected an array, got \'null\' (null).');
    }

    /**
     * The scope map refuses an entry changed after boot to one boot would
     * refuse, rather than skipping it, whether built directly or through the
     * container.
     *
     * @return void
     */
    public function testTheScopeMapRefusesAnEntryChangedAfterBoot(): void
    {
        foreach ([['editor' => 'posts:*'], ['editor' => []], [5], ['editor' => ['posts:*', 5]], 'editor'] as $value) {
            $this->assertRefused(static fn () => SessionScopes::fromConfig($value), 'authorization.session.scopes');
        }

        $this->config()->set('authorization.session.scopes', ['editor' => [null]]);
        $this->container()->forgetScopedInstances();

        $this->assertRefused(fn () => $this->container()->make(SessionScopes::class), 'authorization.session.scopes');

        $this->config()->set('authorization.session', 'none');
        $this->container()->forgetScopedInstances();

        $this->assertRefused(fn () => $this->container()->make(SessionScopes::class), 'authorization.session', 'expected an array, got \'none\' (string).');
    }

    /**
     * The context key catalogue and the check context factory refuse context
     * keys or sources changed after boot to a shape boot would refuse, before
     * resolving any source.
     *
     * @return void
     */
    public function testTheContextBindingsRefuseAValueChangedAfterBoot(): void
    {
        $app = $this->container();

        $this->config()->set('authorization.context.keys', ['tenant' => 'plan']);

        $this->assertRefused(static fn () => ContextBindings::catalogue($app), 'authorization.context.keys');

        $this->config()->set('authorization.context.keys', 'none');

        $this->assertRefused(static fn () => ContextBindings::catalogue($app), 'authorization.context.keys');

        $this->config()->set('authorization.context.sources', ['Missing\Source']);

        $this->assertRefused(static fn () => ContextBindings::factory($app), 'authorization.context.sources.0', 'class \'Missing\Source\' does not exist.');

        $this->config()->set('authorization.context.sources', null);

        $this->assertRefused(static fn () => ContextBindings::factory($app), 'authorization.context.sources');
    }

    /**
     * The attribute providers refuse a map changed after boot to one that does
     * not map a morph type to a provider class, before resolving any.
     *
     * @return void
     */
    public function testTheAttributeProvidersRefuseAMapChangedAfterBoot(): void
    {
        $app = $this->container();

        $this->config()->set('authorization.attributes.resources', ['post' => \stdClass::class]);

        $this->assertRefused(static fn () => AttributeProviders::fromConfig($app), 'authorization.attributes.resources.post');

        $this->config()->set('authorization.attributes.resources', []);
        $this->config()->set('authorization.attributes.subjects', 'none');

        $this->assertRefused(static fn () => AttributeProviders::fromConfig($app), 'authorization.attributes.subjects');

        $this->config()->set('authorization.attributes', null);

        $this->assertRefused(static fn () => AttributeProviders::fromConfig($app), 'authorization.attributes', 'expected an array, got \'null\' (null).');
    }

    /**
     * The listed grant hooks refuse a list changed after boot to one boot would
     * refuse, before building any hook.
     *
     * @return void
     */
    public function testTheGrantHooksRefuseAListChangedAfterBoot(): void
    {
        $app = $this->container();

        foreach (['none' => 'authorization.grant_hooks', 'map' => 'authorization.grant_hooks', 'class' => 'authorization.grant_hooks.0'] as $case => $key) {
            $value = match ($case) {
                'none'  => 'none',
                'map'   => ['hook' => \stdClass::class],
                default => [\stdClass::class],
            };

            $this->config()->set('authorization.grant_hooks', $value);

            $this->assertRefused(static fn () => GrantHooks::fromConfig($app), $key);
        }
    }

    /**
     * The connection is the default one when unset or empty, and a value
     * changed after boot that is not a string is refused, never read as the
     * default connection.
     *
     * @return void
     */
    public function testTheConnectionRefusesAValueChangedAfterBoot(): void
    {
        $this->config()->set('authorization.connection', '');

        self::assertNull(AuthorizationConnection::name());

        $this->config()->set('authorization.connection', null);

        self::assertNull(AuthorizationConnection::name());

        $this->config()->set('authorization.connection', 5);

        $this->assertRefused(static fn () => AuthorizationConnection::name(), 'authorization.connection', 'expected a database connection name, got 5 (int).');

        $this->config()->set('authorization.connection', null);
    }

    /**
     * Usage tracking refuses a `usage` block changed after boot to something
     * that is not an array, rather than reading tracking as off.
     *
     * @return void
     */
    public function testUsageTrackingRefusesABlockChangedAfterBoot(): void
    {
        $this->config()->set('authorization.usage', 'on');

        $this->assertRefused(static fn () => UsageTracking::isEnabled(), 'authorization.usage', 'expected an array, got \'on\' (string).');
    }

    /**
     * Return the bound configuration.
     *
     * @return \Illuminate\Contracts\Config\Repository
     */
    private function config(): ConfigRepository
    {
        return $this->container()->make(ConfigRepository::class);
    }

    /**
     * Assert the callback is refused with the given config key, and the given
     * reason when one is given.
     *
     * @param  callable(): mixed  $callback
     * @param  string  $key
     * @param  string|null  $reason
     * @return void
     */
    private function assertRefused(callable $callback, string $key, ?string $reason = null): void
    {
        try {
            $callback();

            self::fail("InvalidAuthorizationConfigException was not thrown for {$key}.");
        } catch (InvalidAuthorizationConfigException $exception) {
            self::assertSame($key, $exception->getConfigKey(), $exception->getMessage());

            if ($reason !== null) {
                self::assertSame($reason, $exception->getReason());
            }
        }
    }
}
