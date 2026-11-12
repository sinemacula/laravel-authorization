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
use SineMacula\Laravel\Authorization\Config\TableNames;
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
        '2026_11_12_000001_create_break_glass_activations_table',
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
                'authorizable_boundaries', 'guardrails', 'grant_usage', 'usage_coverage', 'break_glass'],
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
        $keys  = \implode(', ', TableConfigValidator::keys());
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
            self::assertContains($names['break_glass'] . '_role_id_foreign', RecordingBlueprint::$names);
            self::assertSame(TableConfigValidator::IDENTIFIER_LENGTH, \strlen($names['break_glass'] . '_role_id_foreign'));
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
     * The break-glass table's default name is not its key's own: it is
     * prefixed, its key's own name is a name set explicitly, and a name another
     * table takes is refused as its duplicate, whether left out or set to the
     * default.
     *
     * @return void
     */
    public function testTheBreakGlassTableTakesItsOwnDefaultName(): void
    {
        self::assertSame('app_break_glass_activations', TableConfigValidator::prefixed('break_glass', 'app_'));
        self::assertSame('app_break_glass_activations', TableConfigValidator::effective('break_glass', 'break_glass_activations', 'app_'));
        self::assertSame('break_glass', TableConfigValidator::effective('break_glass', 'break_glass', 'app_'));
        self::assertSame(
            ['authorization.tables.break_glass', 'duplicate', 'a name no other table has', 'string'],
            self::refusedSetting(static fn () => TableConfigValidator::validate(['roles' => 'break_glass_activations'])),
        );
        $named = ['prefix' => 'x_', 'roles' => 'X_Break_Glass_Activations', 'break_glass' => 'break_glass_activations'];

        self::assertSame(
            ['authorization.tables.break_glass', 'duplicate', 'a name no other table has', 'string'],
            self::refusedSetting(static fn () => TableConfigValidator::validate($named)),
        );

        TableConfigValidator::validate(['roles' => 'break_glass']);
    }

    /**
     * The block may set the prefix beside the thirteen tables, and a prefix
     * that is empty, or a lower-case letter, then lower-case letters, digits
     * and underscores, of at most 16 characters, is accepted.
     *
     * @return void
     */
    public function testAPlainPrefixIsAccepted(): void
    {
        TableConfigValidator::validate(['prefix' => '']);
        TableConfigValidator::validate(['prefix' => 'app_']);
        TableConfigValidator::validate(['prefix' => 'a1_b']);
        TableConfigValidator::validate(['prefix' => \str_repeat('p', 16)]);

        self::assertSame(16, TableConfigValidator::PREFIX_LENGTH);
        self::assertSame(['prefix', ...\array_keys(TableConfigValidator::LENGTHS)], TableConfigValidator::keys());
        self::assertSame('', TableConfigValidator::prefix(''));
        self::assertSame('app_', TableConfigValidator::prefix('app_'));
    }

    /**
     * Return each prefix refused, with the code and why.
     *
     * @return iterable<string, array{mixed, string, string}>
     */
    public static function refusedPrefixes(): iterable
    {
        $shape = 'is not a lower-case letter, then lower-case letters, digits and underscores.';
        $long  = \str_repeat('p', 17);

        yield 'null' => [null, 'invalid_type', 'expected a table name prefix, got \'null\' (null).'];
        yield 'an int' => [5, 'invalid_type', 'expected a table name prefix, got 5 (int).'];
        yield 'a list' => [['app_'], 'invalid_type', 'expected a table name prefix, got \'array\' (array).'];
        yield 'an upper-case letter' => ['App_', 'invalid_value', "prefix 'App_' {$shape}"];
        yield 'a leading digit' => ['1app_', 'invalid_value', "prefix '1app_' {$shape}"];
        yield 'a leading underscore' => ['_app', 'invalid_value', "prefix '_app' {$shape}"];
        yield 'a hyphen' => ['app-', 'invalid_value', "prefix 'app-' {$shape}"];
        yield 'a dot' => ['auth.', 'invalid_value', "prefix 'auth.' {$shape}"];
        yield 'a trailing newline' => ["app\n", 'invalid_value', "prefix 'app\n' {$shape}"];
        yield 'over 16 characters' => [$long, 'out_of_range', "prefix '{$long}' is longer than 16 characters."];
    }

    /**
     * A prefix that is not a string, empty or a lower-case identifier fragment
     * of at most 16 characters is refused under its own path, structured.
     *
     * @param  mixed  $prefix
     * @param  string  $code
     * @param  string  $reason
     * @return void
     */
    #[DataProvider('refusedPrefixes')]
    public function testAMalformedPrefixIsRefused(mixed $prefix, string $code, string $reason): void
    {
        $expected = 'empty, or a lower-case letter, then lower-case letters, digits and underscores, of at most 16 characters';

        self::assertSame(
            ['authorization.tables.prefix', $code, $expected, \get_debug_type($prefix)],
            self::refusedSetting(static fn () => TableConfigValidator::validate(['prefix' => $prefix])),
        );

        try {
            TableConfigValidator::prefix($prefix);

            self::fail('The prefix was accepted.');
        } catch (InvalidAuthorizationConfigException $exception) {
            self::assertSame($reason, $exception->getReason());
        }
    }

    /**
     * The prefix is put before every name left at its default, the key's own,
     * and before no name set explicitly, which is checked as it is written.
     *
     * @return void
     */
    public function testThePrefixIsPutBeforeTheDefaultNamesAlone(): void
    {
        self::assertSame('app_roles', TableConfigValidator::effective('roles', 'roles', 'app_'));
        self::assertSame('authz_roles', TableConfigValidator::effective('roles', 'authz_roles', 'app_'));
        self::assertSame('roles', TableConfigValidator::effective('roles', 'roles', ''));
        self::assertSame(
            ['authorization.tables.roles', 'invalid_type', 'a plain identifier of at most 39 characters', 'null'],
            self::refusedSetting(static fn () => TableConfigValidator::effective('roles', null, 'app_')),
        );
        self::assertSame(
            ['authorization.tables.permissions', 'out_of_range', 'a plain identifier of at most 39 characters', 'string'],
            self::refusedSetting(static fn () => TableConfigValidator::validate(['prefix' => 'app_', 'permissions' => \str_repeat('p', 40)])),
        );
        self::assertSame(
            ['authorization.tables.permissions', 'duplicate', 'a name no other table has', 'string'],
            self::refusedSetting(static fn () => TableConfigValidator::validate(['prefix' => 'x_', 'roles' => 'x_permissions'])),
        );
        self::assertSame(
            ['authorization.tables.policies', 'duplicate', 'a name no other table has', 'string'],
            self::refusedSetting(static fn () => TableConfigValidator::validate(['prefix' => 'x_', 'roles' => 'X_Policies', 'policies' => 'policies'])),
        );

        TableConfigValidator::validate(['prefix' => 'app_', 'roles' => 'roles', 'permissions' => 'permissions', 'policies' => 'app_policies2']);
    }

    /**
     * Each default name with the prefix before it is bounded as an explicit
     * name is: the longest that fits is accepted, and one character more is
     * refused under the prefix's path, as the prefix made it too long. The
     * longest prefix allowed fits every default.
     *
     * @return void
     */
    public function testAPrefixPushingADefaultPastItsBoundIsRefused(): void
    {
        foreach (TableConfigValidator::LENGTHS as $key => $length) {
            $default = TableNames::defaultName($key);
            $room    = $length - \strlen($default);
            $fits    = \str_repeat('p', $room);
            $over    = $fits . 'p';
            $reason  = "prefix '{$over}' makes authorization.tables.{$key} '{$over}{$default}', longer than {$length} characters, which leaves no room for the names of its "
                . 'indexes and keys.';

            self::assertGreaterThan(TableConfigValidator::PREFIX_LENGTH, $room, $key);
            self::assertSame($fits . $default, TableConfigValidator::prefixed($key, $fits));
            self::assertSame(
                ['authorization.tables.prefix', 'out_of_range', "a prefix of at most {$length} characters less the length of '{$default}'", 'string'],
                self::refusedSetting(static fn () => TableConfigValidator::prefixed($key, $over)),
            );

            try {
                TableConfigValidator::effective($key, $default, $over);

                self::fail("A prefix pushing {$key} past its bound was accepted.");
            } catch (InvalidAuthorizationConfigException $exception) {
                self::assertSame($reason, $exception->getReason());
            }
        }

        self::assertSame('unknown_key', self::refusedSetting(static fn () => TableConfigValidator::prefixed('rols', 'app_'))[1]);
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
