<?php

declare(strict_types = 1);

namespace Tests\Unit\Diagnostics;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Config\TableConfigValidator;
use SineMacula\Laravel\Authorization\Diagnostics\TableReader;

/**
 * Unit tests for reading the prefix of the tables' default names and the name
 * each table takes, as the configuration report shows them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TableReader::class)]
final class TableReaderTest extends TestCase
{
    /**
     * Without a prefix or a name set, every table takes the key's own name, in
     * the order the shipped configuration lists them.
     *
     * @return void
     */
    public function testEveryTableLeftOutTakesItsOwnName(): void
    {
        $read = (new TableReader(['connection' => null]))->read();

        self::assertSame('', $read['prefix']);
        self::assertSame(\array_keys(TableConfigValidator::LENGTHS), \array_column($read['names'], 'key'));
        self::assertSame(\array_keys(TableConfigValidator::LENGTHS), \array_column($read['names'], 'name'));
        self::assertNotContains(true, \array_column($read['names'], 'explicit'));
    }

    /**
     * A name left at its default takes the prefix, one set explicitly is shown
     * as written, and one refused is not shown.
     *
     * @return void
     */
    public function testThePrefixIsPutBeforeTheDefaultNames(): void
    {
        $read = (new TableReader(['tables' => ['prefix' => 'app_', 'roles' => 'authz_roles', 'permissions' => 'permissions', 'policies' => 'a b']]))->read();

        self::assertSame('app_', $read['prefix']);
        self::assertSame([
            ['key' => 'roles', 'name' => 'authz_roles', 'explicit' => true],
            ['key' => 'permissions', 'name' => 'app_permissions', 'explicit' => false],
            ['key' => 'policies', 'name' => null, 'explicit' => true],
            ['key' => 'role_permissions', 'name' => 'app_role_permissions', 'explicit' => false],
        ], \array_slice($read['names'], 0, 4));
    }

    /**
     * A refused prefix is not shown, nor any name left at its default, while a
     * name set explicitly still is.
     *
     * @return void
     */
    public function testARefusedPrefixHidesTheDefaultNames(): void
    {
        $read = (new TableReader(['tables' => ['prefix' => 'App_', 'roles' => 'authz_roles']]))->read();

        self::assertNull($read['prefix']);
        self::assertSame([
            ['key' => 'roles', 'name' => 'authz_roles', 'explicit' => true],
            ['key' => 'permissions', 'name' => null, 'explicit' => false],
        ], \array_slice($read['names'], 0, 2));
    }

    /**
     * A block, or a configuration, that is not an array shows neither the
     * prefix nor any name, and tells no name as set explicitly.
     *
     * @return void
     */
    public function testABlockThatIsNotAnArrayShowsNothing(): void
    {
        foreach ([['tables' => 'roles'], 'authorization'] as $root) {
            $read = (new TableReader($root))->read();

            self::assertNull($read['prefix']);
            self::assertCount(13, $read['names']);
            self::assertSame([null], \array_values(\array_unique(\array_column($read['names'], 'name'))));
            self::assertSame([false], \array_values(\array_unique(\array_column($read['names'], 'explicit'))));
        }

        self::assertSame(['prefix' => null, 'names' => []], TableReader::UNREAD);
    }
}
