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
 * the key's own, a name left at its default takes the prefix while one set
 * explicitly is used as written, and a name, prefix or block changed to one
 * that cannot name a table is refused, never read as the package's name for the
 * table.
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
     * Return prefixes with whether each is valid.
     *
     * @return iterable<string, array{string, bool}>
     */
    public static function prefixes(): iterable
    {
        yield 'empty' => ['', true];
        yield 'plain' => ['authz_', true];
        yield 'the longest' => [\str_repeat('a', 16), true];
        yield 'one too long' => [\str_repeat('a', 17), false];
        yield 'upper case' => ['Authz_', false];
        yield 'a leading digit' => ['1authz_', false];
        yield 'a leading underscore' => ['_authz', false];
        yield 'a dash' => ['authz-', false];
        yield 'a space' => ['authz ', false];
        yield 'a trailing newline' => ["authz\n", false];
    }

    /**
     * The prefix check accepts exactly what boot validation accepts: empty, or
     * a lower-case letter followed by lower-case letters, digits and
     * underscores, of at most 16 characters.
     *
     * @param  string  $prefix
     * @param  bool  $isValid
     * @return void
     */
    #[DataProvider('prefixes')]
    public function testAPrefixIsCheckedAsBootChecksIt(string $prefix, bool $isValid): void
    {
        self::assertSame($isValid, TableNames::isValidPrefix($prefix));
    }

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
     * A name left out, or set to the key's own, is the default and takes the
     * prefix; a name that differs from the key's own is set explicitly and is
     * used as written, without it.
     *
     * @return void
     */
    public function testThePrefixIsPutBeforeEveryDefaultName(): void
    {
        $config = new Repository(['authorization' => ['tables' => ['prefix' => 'app_', 'roles' => 'roles', 'permissions' => 'authz_permissions']]]);

        self::assertSame('app_roles', TableNames::get('roles', $config));
        self::assertSame('authz_permissions', TableNames::get('permissions', $config));
        self::assertSame('app_policies', TableNames::get('policies', $config));
        self::assertSame('app_', TableNames::prefix($config));
        $config = new Repository(['authorization' => ['tables' => ['prefix' => 'app_', 'permissions' => 'permissions']]]);

        self::assertSame('app_permissions', TableNames::get('permissions', $config));
    }

    /**
     * A prefix left out, or empty, puts nothing before a name, and none is read
     * without the block or the authorization config.
     *
     * @return void
     */
    public function testAnEmptyPrefixLeavesEveryNameAsItIs(): void
    {
        self::assertSame('roles', TableNames::get('roles', new Repository(['authorization' => ['tables' => ['prefix' => '']]])));
        self::assertSame('', TableNames::prefix(new Repository(['authorization' => ['tables' => ['roles' => 'authz_roles']]])));
        self::assertSame('', TableNames::prefix(new Repository(['authorization' => []])));
        self::assertSame('', TableNames::prefix(new Repository));
    }

    /**
     * Only the key's own name is the default: a value that differs from it in
     * any way, its case among them, is set explicitly.
     *
     * @return void
     */
    public function testOnlyTheKeysOwnNameIsTheDefault(): void
    {
        self::assertTrue(TableNames::isDefault('roles', 'roles'));
        self::assertFalse(TableNames::isDefault('roles', 'Roles'));
        self::assertFalse(TableNames::isDefault('roles', 'app_roles'));
        self::assertFalse(TableNames::isDefault('roles', null));
        self::assertSame('Roles', TableNames::get('roles', new Repository(['authorization' => ['tables' => ['prefix' => 'app_', 'roles' => 'Roles']]])));
    }

    /**
     * Whether a name was set explicitly is told by its value alone, so the
     * configuration read from the config file with the environment, and the
     * same configuration cached, as `config:cache` writes it with no
     * environment left to read, name every table alike: a name the environment
     * sets to the key's own is the default there too, and takes the prefix.
     *
     * @return void
     */
    public function testACachedConfigurationNamesTheTablesAlike(): void
    {
        $env = ['AUTHORIZATION_TABLE_PREFIX' => 'app_', 'AUTHORIZATION_TABLE_ROLES' => 'authz_roles', 'AUTHORIZATION_TABLE_PERMISSIONS' => 'permissions'];

        foreach ($env as $variable => $value) {
            $_SERVER[$variable] = $value;
        }

        try {
            /** @var array<string, mixed> $loaded */
            $loaded = require \dirname(__DIR__, 3) . '/config/authorization.php';
        } finally {
            foreach (\array_keys($env) as $name) {
                unset($_SERVER[$name]);
            }
        }

        $file = (string) \tempnam(\sys_get_temp_dir(), 'authorization-config');

        try {
            \file_put_contents($file, '<?php return ' . \var_export($loaded, true) . ';' . \PHP_EOL);

            /** @var array<string, mixed> $cached */
            $cached = require $file;
        } finally {
            \unlink($file);
        }

        foreach ([$loaded, $cached] as $authorization) {
            $config = new Repository(['authorization' => $authorization]);

            self::assertSame('app_', TableNames::prefix($config));
            self::assertSame('authz_roles', TableNames::get('roles', $config));
            self::assertSame('app_permissions', TableNames::get('permissions', $config));
            self::assertSame('app_usage_coverage', TableNames::get('usage_coverage', $config));
        }

        self::assertSame('', TableNames::prefix(new Repository(['authorization' => require \dirname(__DIR__, 3) . '/config/authorization.php'])));
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
        yield 'a null prefix' => [['tables' => ['prefix' => null]], 'authorization.tables.prefix', 'expected a table name prefix, got \'null\' (null).'];
        yield 'an int prefix' => [['tables' => ['prefix' => 5]], 'authorization.tables.prefix', 'expected a table name prefix, got 5 (int).'];
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
