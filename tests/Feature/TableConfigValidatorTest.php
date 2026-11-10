<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authorization\Config\TableConfigValidator;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationConfigException;
use Tests\Concerns\ReadsRefusedSettings;
use Tests\Fixtures\Database\RecordingBlueprint;
use Tests\TestCase;

/**
 * Feature tests for the boot-time validation of `authorization.tables`, and the
 * proof of each table's bound: migrated with the longest names allowed, every
 * index and key name a migration builds fits in the limit.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(TableConfigValidator::class)]
final class TableConfigValidatorTest extends TestCase
{
    use ReadsRefusedSettings;

    /** @var list<string> The package migrations, in the order they run. */
    private const array MIGRATIONS = [
        '2026_04_14_000001_create_roles_table',
        '2026_04_14_000002_create_permissions_table',
        '2026_04_14_000003_create_policies_table',
        '2026_04_14_000004_create_role_permissions_table',
        '2026_04_14_000005_create_authorizable_roles_table',
        '2026_04_14_000006_create_authorizable_permissions_table',
        '2026_04_14_000007_create_authorizable_policies_table',
        '2026_04_14_000008_create_resource_policies_table',
        '2026_04_14_000009_create_authorizable_boundaries_table',
        '2026_04_14_000010_create_guardrails_table',
        '2026_11_08_000001_add_access_review_indexes',
        '2026_11_09_000001_create_grant_usage_tables',
    ];

    /**
     * An empty block takes the keys' own names, and plain identifiers up to
     * each table's bound, distinct from one another, are accepted.
     *
     * @return void
     */
    public function testPlainDistinctNamesAreAccepted(): void
    {
        TableConfigValidator::validate([]);
        TableConfigValidator::validate(['roles' => 'auth_roles', 'permissions' => '_permissions2', 'guardrails' => 'Guard_Rails']);
        TableConfigValidator::validate(self::longestNames());

        self::assertSame(63, TableConfigValidator::IDENTIFIER_LENGTH);
        self::assertSame(
            ['roles', 'permissions', 'policies', 'role_permissions', 'authorizable_roles', 'authorizable_permissions', 'authorizable_policies', 'resource_policies',
                'authorizable_boundaries', 'guardrails', 'grant_usage', 'usage_coverage'],
            \array_keys(TableConfigValidator::LENGTHS),
        );
    }

    /**
     * Return each block refused, with the path it is refused under and why.
     *
     * @return iterable<string, array{mixed, string, string}>
     */
    public static function refusedBlocks(): iterable
    {
        $roles = 'authorization.tables.roles';
        $plain = 'is not a plain identifier: a letter or an underscore, then letters, digits and underscores, with no schema.';
        $long  = \str_repeat('r', 40);
        $keys  = \implode(', ', \array_keys(TableConfigValidator::LENGTHS));
        $over  = 'is longer than 39 characters, which leaves no room for the names of its indexes and keys.';

        yield 'null' => [null, 'authorization.tables', 'expected an array, got \'null\' (null).'];
        yield 'a string' => ['roles', 'authorization.tables', 'expected an array, got \'roles\' (string).'];
        yield 'an unknown key' => [['role' => 'roles'], 'authorization.tables.role', "unknown key 'role'; expected one of {$keys}."];
        yield 'a null name' => [['roles' => null], $roles, 'expected a table name, got \'null\' (null).'];
        yield 'an empty name' => [['roles' => ''], $roles, 'expected a table name, got \'\' (string).'];
        yield 'a name that is not a string' => [['roles' => 5], $roles, 'expected a table name, got 5 (int).'];
        yield 'a name qualified by a schema' => [['roles' => 'auth.roles'], $roles, "table 'auth.roles' {$plain}"];
        yield 'a name starting with a digit' => [['roles' => '1roles'], $roles, "table '1roles' {$plain}"];
        yield 'a name with a hyphen' => [['roles' => 'auth-roles'], $roles, "table 'auth-roles' {$plain}"];
        yield 'a name with a space' => [['roles' => 'roles '], $roles, "table 'roles ' {$plain}"];
        yield 'a name with a trailing newline' => [['roles' => "roles\n"], $roles, "table 'roles\n' {$plain}"];
        yield 'a name with a quote' => [['roles' => 'roles`'], $roles, "table 'roles`' {$plain}"];
        yield 'a name over its bound' => [['roles' => $long], $roles, "table '{$long}' {$over}"];
        yield 'two keys naming one table' => [['permissions' => 'roles'], 'authorization.tables.permissions', 'table \'roles\' is already the name of authorization.tables.roles.'];
        yield 'two names differing in case' => [
            ['roles' => 'Shared', 'permissions' => 'shared'],
            'authorization.tables.permissions',
            'table \'shared\' is already the name of authorization.tables.roles.',
        ];
        yield 'a name another key leaves out' => [
            ['grant_usage' => 'guardrails'],
            'authorization.tables.grant_usage',
            'table \'guardrails\' is already the name of authorization.tables.guardrails.',
        ];
    }

    /**
     * A block that is not an array, or names a table that is not a plain
     * identifier within its bound, or names one two keys name, is refused under
     * the key.
     *
     * @param  mixed  $config
     * @param  string  $path
     * @param  string  $reason
     * @return void
     */
    #[DataProvider('refusedBlocks')]
    public function testAMalformedBlockIsRefused(mixed $config, string $path, string $reason): void
    {
        try {
            TableConfigValidator::validate($config);

            self::fail('The block was accepted.');
        } catch (InvalidAuthorizationConfigException $exception) {
            self::assertSame($path, $exception->getConfigKey());
            self::assertSame($reason, $exception->getReason());
        }
    }

    /**
     * Each table's bound is exactly the longest name accepted.
     *
     * @return void
     */
    public function testEachBoundIsTheLongestNameAccepted(): void
    {
        foreach (TableConfigValidator::LENGTHS as $key => $length) {
            TableConfigValidator::validate([$key => \str_repeat('t', $length)]);

            try {
                TableConfigValidator::validate([$key => \str_repeat('t', $length + 1)]);

                self::fail("A name over the bound of {$key} was accepted.");
            } catch (InvalidAuthorizationConfigException $exception) {
                self::assertSame("authorization.tables.{$key}", $exception->getConfigKey());
            }
        }
    }

    /**
     * Migrated with the longest names allowed, every index, unique index,
     * primary key and foreign key name the migrations build, as Laravel names
     * them and as the database keeps them, fits in the limit, and the tables
     * are dropped cleanly again.
     *
     * @return void
     */
    public function testTheMigrationsFitTheLongestNamesAllowed(): void
    {
        $app    = $this->container();
        $config = $app->make(ConfigRepository::class);
        $names  = self::longestNames();

        foreach ($names as $key => $name) {
            $config->set("authorization.tables.{$key}", $name);
        }

        RecordingBlueprint::$names = [];

        $app->bind(Blueprint::class, static function (Container $app, array $parameters): Blueprint {
            /** @var array{connection: \Illuminate\Database\Connection, table: string, callback: (\Closure(\Illuminate\Database\Schema\Blueprint): void)|null} $parameters */
            return new RecordingBlueprint($parameters['connection'], $parameters['table'], $parameters['callback']);
        });

        try {
            foreach (self::MIGRATIONS as $file) {
                self::runMigration($file, 'up');
            }

            $built = [...RecordingBlueprint::$names, ...self::keptNames(\array_values($names))];

            self::assertNotEmpty(RecordingBlueprint::$names);

            foreach ($built as $name) {
                self::assertLessThanOrEqual(TableConfigValidator::IDENTIFIER_LENGTH, \strlen($name), $name);
            }

            self::assertContains($names['role_permissions'] . '_role_id_permission_id_primary', RecordingBlueprint::$names);
            self::assertContains($names['authorizable_permissions'] . '_permission_id_foreign', RecordingBlueprint::$names);
        } finally {
            foreach (\array_reverse(self::MIGRATIONS) as $file) {
                self::runMigration($file, 'down');
            }

            unset($app[Blueprint::class]);
        }

        foreach ($names as $name) {
            self::assertFalse(Schema::hasTable($name), $name);
        }
    }

    /**
     * Each table's name is checked on its own, and a name another table has is
     * refused as a duplicate, each refusal structured.
     *
     * @return void
     */
    public function testEachNameIsCheckedOnItsOwn(): void
    {
        self::assertSame('roles', TableConfigValidator::name('roles', 'roles'));
        self::assertSame(['admins' => 'roles'], TableConfigValidator::distinct('roles', 'Admins', []));
        self::assertSame(
            ['authorization.tables.roles', 'invalid_type', 'a plain identifier of at most 39 characters', 'int'],
            self::refusedSetting(static fn () => TableConfigValidator::name('roles', 3)),
        );
        self::assertSame(
            ['authorization.tables.roles', 'invalid_value', 'a plain identifier of at most 39 characters', 'string'],
            self::refusedSetting(static fn () => TableConfigValidator::name('roles', 'a b')),
        );
        self::assertSame('out_of_range', self::refusedSetting(static fn () => TableConfigValidator::name('roles', \str_repeat('r', 40)))[1]);
        self::assertSame('unknown_key', self::refusedSetting(static fn () => TableConfigValidator::name('rols', 'roles'))[1]);
        self::assertSame(
            ['authorization.tables.permissions', 'duplicate', 'a name no other table has', 'string'],
            self::refusedSetting(static fn () => TableConfigValidator::distinct('permissions', 'ROLES', ['roles' => 'roles'])),
        );
    }

    /**
     * Return the longest name allowed for each table, each distinct.
     *
     * @return array<string, string>
     */
    private static function longestNames(): array
    {
        $names = [];

        foreach (TableConfigValidator::LENGTHS as $key => $length) {
            $names[$key] = \substr(\str_repeat($key . '_', 8), 0, $length);
        }

        return $names;
    }

    /**
     * Return the names of the indexes and foreign keys the database keeps on
     * the tables, but those SQLite names itself for a key no migration names,
     * as it sets no limit on them.
     *
     * @param  list<string>  $tables
     * @return list<string>
     */
    private static function keptNames(array $tables): array
    {
        $kept = [];

        foreach ($tables as $table) {
            foreach ([...Schema::getIndexes($table), ...Schema::getForeignKeys($table)] as $entry) {
                $name = $entry['name'] ?? null;

                if (!\is_string($name) || \str_starts_with($name, 'sqlite_autoindex_')) {
                    continue;
                }

                $kept[] = $name;
            }
        }

        return $kept;
    }

    /**
     * Run the package migration in the file in the direction given.
     *
     * @param  string  $file
     * @param  string  $direction
     * @return void
     */
    private static function runMigration(string $file, string $direction): void
    {
        $migration = require __DIR__ . '/../../database/migrations/' . $file . '.php';

        \assert($migration instanceof Migration && \method_exists($migration, 'up') && \method_exists($migration, 'down'));

        $direction === 'up' ? $migration->up() : $migration->down();
    }
}
