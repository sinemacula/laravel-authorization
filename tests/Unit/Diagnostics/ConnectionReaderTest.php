<?php

declare(strict_types = 1);

namespace Tests\Unit\Diagnostics;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Diagnostics\ConnectionReader;

/**
 * Unit tests for reading the database connection, cache store and queue
 * connection from the configuration alone.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConnectionReader::class)]
final class ConnectionReaderTest extends TestCase
{
    /**
     * Each name the package's settings leave out is the default's, a cache
     * store left out is none, and each driver is read; nothing else of an entry
     * is read and nothing is tested.
     *
     * @return void
     */
    public function testTheDefaultsAreShown(): void
    {
        $read = (new ConnectionReader(self::config([])))->read();

        self::assertSame(['name' => 'main', 'chosen' => 'default', 'driver' => 'pgsql', 'connectivity' => 'not_tested', 'redacted' => []], $read['database']);
        self::assertSame(['store' => null, 'chosen' => 'none', 'driver' => null, 'redacted' => []], $read['cache']);
        self::assertSame(['connection' => 'jobs', 'chosen' => 'default', 'driver' => 'redis', 'queue' => null, 'redacted' => []], $read['queue']);
        self::assertStringNotContainsString('Hunter2', (string) \json_encode($read));
    }

    /**
     * Each name the package's settings set is shown as configured, with its
     * driver, or none when the map has no such entry.
     *
     * @return void
     */
    public function testTheConfiguredNamesAreShown(): void
    {
        $read = (new ConnectionReader(self::config([
            'connection' => 'audit',
            'cache'      => ['store' => 'shared'],
            'usage'      => ['connection' => 'missing', 'queue' => 'usage'],
        ])))->read();

        self::assertSame(['name' => 'audit', 'chosen' => 'configured', 'driver' => 'mysql', 'connectivity' => 'not_tested', 'redacted' => []], $read['database']);
        self::assertSame(['store' => 'shared', 'chosen' => 'configured', 'driver' => 'redis', 'redacted' => []], $read['cache']);
        self::assertSame(['connection' => 'missing', 'chosen' => 'configured', 'driver' => null, 'queue' => 'usage', 'redacted' => []], $read['queue']);
    }

    /**
     * A name or a driver that is not made of the characters names are, such as
     * a queue's URL, is never shown: it is null, and listed as redacted, as the
     * settings section hides it.
     *
     * @return void
     */
    public function testANameThatIsNoNameIsNeverShown(): void
    {
        $url  = 'https://sqs.eu-west-1.amazonaws.com/123456789012/authz-usage';
        $read = (new ConnectionReader(new Repository([
            'authorization' => ['connection' => 'pgsql://u:Hunter2@h/d', 'usage' => ['queue' => $url, 'connection' => 'jobs']],
            'database'      => ['connections' => ['pgsql://u:Hunter2@h/d' => ['driver' => 'pgsql://u:Hunter2@h/d']]],
            'queue'         => ['connections' => ['jobs' => ['driver' => 'sqs']]],
        ])))->read();

        self::assertSame(['name' => null, 'chosen' => 'configured', 'driver' => null, 'connectivity' => 'not_tested', 'redacted' => ['name', 'driver']], $read['database']);
        self::assertSame(['connection' => 'jobs', 'chosen' => 'configured', 'driver' => 'sqs', 'queue' => null, 'redacted' => ['queue']], $read['queue']);
        self::assertStringNotContainsString('Hunter2', (string) \json_encode($read));
        self::assertStringNotContainsString('123456789012', (string) \json_encode($read));
    }

    /**
     * An empty name, or one that is not a string, is taken for none: the
     * default's name is shown, or none for the cache store.
     *
     * @return void
     */
    public function testAnEmptyOrNonStringNameIsNone(): void
    {
        $read = (new ConnectionReader(self::config([
            'connection' => '',
            'cache'      => ['store' => ''],
            'usage'      => ['connection' => 3, 'queue' => ''],
        ])))->read();

        self::assertSame(['main', 'default'], [$read['database']['name'], $read['database']['chosen']]);
        self::assertSame([null, 'none'], [$read['cache']['store'], $read['cache']['chosen']]);
        self::assertSame(['jobs', 'default', null], [$read['queue']['connection'], $read['queue']['chosen'], $read['queue']['queue']]);
    }

    /**
     * A map of connections that is not an array, or an entry that is not one,
     * gives no driver.
     *
     * @return void
     */
    public function testAMalformedMapGivesNoDriver(): void
    {
        $read = (new ConnectionReader(new Repository([
            'database' => ['default' => 'main', 'connections' => 'x'],
            'queue'    => ['default' => 'jobs', 'connections' => ['jobs' => 'redis']],
        ])))->read();

        self::assertSame(['main', null], [$read['database']['name'], $read['database']['driver']]);
        self::assertSame(['jobs', null], [$read['queue']['connection'], $read['queue']['driver']]);
    }

    /**
     * What the report holds when the connection could not be read keeps each
     * part, as null, so its JSON is still an object.
     *
     * @return void
     */
    public function testTheUnreadConnectionKeepsItsShape(): void
    {
        self::assertSame('{"database":null,"cache":null,"queue":null}', \json_encode(ConnectionReader::UNREAD));
    }

    /**
     * Return a configuration holding the authorization settings given and
     * entries holding credentials.
     *
     * @param  array<string, mixed>  $authorization
     * @return \Illuminate\Config\Repository
     */
    private static function config(array $authorization): Repository
    {
        return new Repository([
            'authorization' => $authorization,
            'database'      => [
                'default'     => 'main',
                'connections' => [
                    'main'  => ['driver' => 'pgsql', 'password' => 'Hunter2', 'url' => 'pgsql://u:Hunter2@h/d'],
                    'audit' => ['driver' => 'mysql', 'password' => 'Hunter2'],
                ],
            ],
            'cache' => ['default' => 'file', 'stores' => ['shared' => ['driver' => 'redis', 'password' => 'Hunter2']]],
            'queue' => ['default' => 'jobs', 'connections' => ['jobs' => ['driver' => 'redis']]],
        ]);
    }
}
