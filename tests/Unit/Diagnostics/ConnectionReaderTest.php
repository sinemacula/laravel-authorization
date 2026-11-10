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

        self::assertSame(['name' => 'main', 'chosen' => 'default', 'driver' => 'pgsql', 'connectivity' => 'not_tested'], $read['database']);
        self::assertSame(['store' => null, 'chosen' => 'none', 'driver' => null], $read['cache']);
        self::assertSame(['connection' => 'jobs', 'chosen' => 'default', 'driver' => 'redis', 'queue' => null], $read['queue']);
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

        self::assertSame(['name' => 'audit', 'chosen' => 'configured', 'driver' => 'mysql', 'connectivity' => 'not_tested'], $read['database']);
        self::assertSame(['store' => 'shared', 'chosen' => 'configured', 'driver' => 'redis'], $read['cache']);
        self::assertSame(['connection' => 'missing', 'chosen' => 'configured', 'driver' => null, 'queue' => 'usage'], $read['queue']);
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
