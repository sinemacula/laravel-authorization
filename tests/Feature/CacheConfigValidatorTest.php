<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Container\Container;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\AuthorizationServiceProvider;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Config\CacheConfigValidator;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;
use Tests\Concerns\ReadsRefusedSettings;
use Tests\TestCase;

/**
 * Feature tests for the validation and reading of `authorization.cache`: the
 * store, the lifetime of an entry and the prefix of every key, checked at boot
 * and read through the same checks when the resolution cache is built.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(CacheConfigValidator::class)]
#[CoversClass(AuthorizationServiceProvider::class)]
final class CacheConfigValidatorTest extends TestCase
{
    use ReadsRefusedSettings;

    /** @var string The path of the lifetime. */
    private const string TTL = 'authorization.cache.ttl';

    /** @var string The path of the prefix. */
    private const string PREFIX = 'authorization.cache.prefix';

    /** @var string The path of the store. */
    private const string STORE = 'authorization.cache.store';

    /**
     * An empty block takes every default, and a configured store, a whole
     * lifetime of at least 1, written as the environment gives it too, and a
     * non-empty prefix are accepted.
     *
     * @return void
     */
    public function testAWellFormedBlockIsAccepted(): void
    {
        CacheConfigValidator::validate([], $this->container());
        CacheConfigValidator::validate(['store' => null, 'ttl' => 1, 'prefix' => 'a'], $this->container());
        CacheConfigValidator::validate(['store' => 'array', 'ttl' => '300', 'prefix' => 'authorization'], $this->container());

        self::assertSame(['store', 'ttl', 'prefix'], CacheConfigValidator::SETTINGS);
        self::assertSame(300, CacheConfigValidator::TTL);
        self::assertSame('authorization', CacheConfigValidator::PREFIX);
        self::assertSame(300, CacheConfigValidator::ttl('300'));
        self::assertSame(1, CacheConfigValidator::ttl(1));
        self::assertSame('cached', CacheConfigValidator::prefix('cached'));
    }

    /**
     * Return each malformed block, with the path it is refused under and why.
     *
     * @return iterable<string, array{mixed, string, string}>
     */
    public static function refusedBlocks(): iterable
    {
        $seconds = 'expected a whole number of seconds of at least 1, got ';
        $prefix  = 'expected a non-empty string, got ';
        $store   = 'expected a cache-store name string, got ';

        yield 'null' => [null, 'authorization.cache', 'expected an array, got \'null\' (null).'];
        yield 'a string' => ['redis', 'authorization.cache', 'expected an array, got \'redis\' (string).'];
        yield 'an unknown key' => [['tll' => 300], 'authorization.cache.tll', 'unknown key \'tll\'; expected one of store, ttl, prefix.'];
        yield 'an empty store' => [['store' => ''], self::STORE, $store . '\'\' (string).'];
        yield 'a store that is not a name' => [['store' => 5], self::STORE, $store . '5 (int).'];
        yield 'a null lifetime' => [['ttl' => null], self::TTL, $seconds . '\'null\' (null).'];
        yield 'a lifetime of 0' => [['ttl' => 0], self::TTL, $seconds . '0 (int).'];
        yield 'a lifetime of 0 as a string' => [['ttl' => '0'], self::TTL, $seconds . '\'0\' (string).'];
        yield 'a negative lifetime' => [['ttl' => -1], self::TTL, $seconds . '-1 (int).'];
        yield 'a lifetime with letters' => [['ttl' => '12abc'], self::TTL, $seconds . '\'12abc\' (string).'];
        yield 'a lifetime as an exponent' => [['ttl' => '1e3'], self::TTL, $seconds . '\'1e3\' (string).'];
        yield 'a padded lifetime' => [['ttl' => ' 5'], self::TTL, $seconds . '\' 5\' (string).'];
        yield 'a decimal lifetime' => [['ttl' => '5.0'], self::TTL, $seconds . '\'5.0\' (string).'];
        yield 'an empty lifetime' => [['ttl' => ''], self::TTL, $seconds . '\'\' (string).'];
        yield 'a fractional lifetime' => [['ttl' => 1.5], self::TTL, $seconds . '1.5 (float).'];
        yield 'a null prefix' => [['prefix' => null], self::PREFIX, $prefix . '\'null\' (null).'];
        yield 'an empty prefix' => [['prefix' => ''], self::PREFIX, $prefix . '\'\' (string).'];
        yield 'a prefix that is not a string' => [['prefix' => ['a']], self::PREFIX, $prefix . '\'array\' (array).'];
    }

    /**
     * A malformed block is refused, naming the path.
     *
     * @param  mixed  $block
     * @param  string  $path
     * @param  string  $reason
     * @return void
     */
    #[DataProvider('refusedBlocks')]
    public function testAMalformedBlockIsRefused(mixed $block, string $path, string $reason): void
    {
        $this->assertRefused(fn () => CacheConfigValidator::validate($block, $this->container()), $path, $reason);
    }

    /**
     * A store the cache manager does not configure is refused, naming the
     * store.
     *
     * @return void
     */
    public function testAStoreNotConfiguredIsRefused(): void
    {
        try {
            CacheConfigValidator::validate(['store' => 'missing'], $this->container());

            self::fail('The store was accepted.');
        } catch (InvalidAuthorizationConfigException $exception) {
            self::assertSame(self::STORE, $exception->getConfigKey());
            self::assertStringStartsWith('cache store \'missing\' is not configured: ', $exception->getReason());
        }
    }

    /**
     * With no store set, the default store is used, and boot does not build it,
     * so a default store the cache manager could not build passes.
     *
     * @return void
     */
    public function testNoStoreSetDoesNotBuildTheDefaultStore(): void
    {
        $this->container()->make(ConfigRepository::class)->set('cache.default', 'unconfigured');

        CacheConfigValidator::validate(['store' => null], $this->container());
        CacheConfigValidator::validate([], $this->container());

        $this->addToAssertionCount(2);
    }

    /**
     * Without a cache manager bound, a store set is checked only for its type,
     * and nothing is bound to build it.
     *
     * @return void
     */
    public function testWithoutACacheManagerOnlyTheStoreTypeIsChecked(): void
    {
        $container = new Container;

        CacheConfigValidator::validate(['store' => 'redis'], $container);

        self::assertFalse($container->bound('cache'));
    }

    /**
     * The resolution cache reads the lifetime as the environment writes it, and
     * refuses a lifetime or a prefix changed after boot to something malformed
     * rather than casting it.
     *
     * @return void
     */
    public function testTheResolutionCacheReadsThroughTheChecks(): void
    {
        $app    = $this->container();
        $config = $app->make(ConfigRepository::class);

        $config->set(self::TTL, '60');

        self::assertInstanceOf(ResolutionCache::class, $app->make(ResolutionCache::class));

        $app->forgetScopedInstances();
        $config->set(self::TTL, null);

        $this->assertRefused(static fn () => $app->make(ResolutionCache::class), self::TTL, 'expected a whole number of seconds of at least 1, got \'null\' (null).');

        $config->set(self::TTL, 300);
        $config->set(self::PREFIX, '');

        $this->assertRefused(static fn () => $app->make(ResolutionCache::class), self::PREFIX, 'expected a non-empty string, got \'\' (string).');
    }

    /**
     * Each refusal of the cache block is structured, the store's name checked
     * without resolving it.
     *
     * @return void
     */
    public function testEachRefusalIsStructured(): void
    {
        self::assertSame(['authorization.cache.prefix', 'invalid_type', 'a non-empty string', 'string'], self::refusedSetting(static fn () => CacheConfigValidator::prefix('')));
        self::assertSame(
            ['authorization.cache.store', 'invalid_type', 'a cache store name or null', 'int'],
            self::refusedSetting(static fn () => CacheConfigValidator::storeName(3)),
        );
        self::assertSame('out_of_range', self::refusedSetting(static fn () => CacheConfigValidator::ttl(0))[1]);
        self::assertSame('missing', CacheConfigValidator::storeName('missing'));
        self::assertSame(
            ['authorization.cache.store', 'unknown_name', 'the name of a configured cache store', 'string'],
            self::refusedSetting(fn () => CacheConfigValidator::validate(['store' => 'missing'], $this->container())),
        );
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
