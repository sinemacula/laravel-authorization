<?php

declare(strict_types = 1);

namespace Tests\Unit\Config;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Config\ConfigValue;
use SineMacula\Laravel\Authorization\Config\TableNames;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;

/**
 * Unit tests for reading a package table's name at run time: a name left out is
 * the key's own, and a name or block changed to one that cannot name a table is
 * refused, never read as the package's name for the table.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TableNames::class)]
#[CoversClass(ConfigValue::class)]
final class TableNamesTest extends TestCase
{
    /**
     * A configured name is read as it is.
     *
     * @return void
     */
    public function testAConfiguredNameIsRead(): void
    {
        $config = new Repository(['authorization' => ['tables' => ['roles' => 'authz_roles']]]);

        self::assertSame('authz_roles', TableNames::get('roles', $config));
    }

    /**
     * A name the configuration leaves out, or a configuration without the block
     * or the authorization config, is the key's own.
     *
     * @return void
     */
    public function testANameLeftOutIsTheKeysOwn(): void
    {
        self::assertSame('permissions', TableNames::get('permissions', new Repository(['authorization' => ['tables' => ['roles' => 'authz_roles']]])));
        self::assertSame('permissions', TableNames::get('permissions', new Repository(['authorization' => []])));
        self::assertSame('permissions', TableNames::get('permissions', new Repository));
    }

    /**
     * Return each configuration refused, with the path it is refused under and
     * why.
     *
     * @return iterable<string, array{array<string, mixed>, string, string}>
     */
    public static function refusedConfigs(): iterable
    {
        yield 'a null name' => [['tables' => ['roles' => null]], 'authorization.tables.roles', 'expected a table name, got \'null\' (null).'];
        yield 'an empty name' => [['tables' => ['roles' => '']], 'authorization.tables.roles', 'expected a table name, got \'\' (string).'];
        yield 'an int name' => [['tables' => ['roles' => 5]], 'authorization.tables.roles', 'expected a table name, got 5 (int).'];
        yield 'a list name' => [['tables' => ['roles' => ['roles']]], 'authorization.tables.roles', 'expected a table name, got \'array\' (array).'];
        yield 'a null block' => [['tables' => null], 'authorization.tables', 'expected an array, got \'null\' (null).'];
        yield 'a string block' => [['tables' => 'roles'], 'authorization.tables', 'expected an array, got \'roles\' (string).'];
    }

    /**
     * A name, or the block holding it, that cannot name a table is refused
     * under its own path, never read as the key's own name.
     *
     * @param  array<string, mixed>  $authorization
     * @param  string  $key
     * @param  string  $reason
     * @return void
     */
    #[DataProvider('refusedConfigs')]
    public function testANameThatCannotNameATableIsRefused(array $authorization, string $key, string $reason): void
    {
        try {
            TableNames::get('roles', new Repository(['authorization' => $authorization]));

            self::fail('InvalidAuthorizationConfigException was not thrown.');
        } catch (InvalidAuthorizationConfigException $exception) {
            self::assertSame($key, $exception->getConfigKey());
            self::assertSame($reason, $exception->getReason());
        }
    }
}
