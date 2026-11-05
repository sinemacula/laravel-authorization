<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Config\Repository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use Tests\Concerns\UsesAnAuthorizationConnection;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Coverage for the `authorization.connection` setting: the name it resolves to,
 * and that the shipped migrations create and drop the package's tables on it
 * while the models and pivots read and write there. Unset, the package's rows
 * stay on the application's default connection, even for a grantee that lives
 * on another.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(AuthorizationConnection::class)]
final class AuthorizationConnectionTest extends TestCase
{
    use UsesAnAuthorizationConnection;

    /** @var list<string> The package's tables, under their default names. */
    private const array TABLES = [
        'roles',
        'permissions',
        'policies',
        'role_permissions',
        'authorizable_roles',
        'authorizable_permissions',
        'authorizable_policies',
    ];

    /**
     * With the setting unset, the package leaves the choice to Laravel.
     *
     * @return void
     */
    public function testNameIsNullWhenUnset(): void
    {
        $this->setConnectionSetting(null);

        self::assertNull(AuthorizationConnection::name());
    }

    /**
     * An empty name, as an empty environment variable gives, counts as unset.
     *
     * @return void
     */
    public function testNameIsNullWhenEmpty(): void
    {
        $this->setConnectionSetting('');

        self::assertNull(AuthorizationConnection::name());
    }

    /**
     * A value that is not a string is never taken for a connection name.
     *
     * @return void
     */
    public function testNameIsNullWhenNotAString(): void
    {
        $this->setConnectionSetting(5);

        self::assertNull(AuthorizationConnection::name());
    }

    /**
     * A configured name is returned as it is.
     *
     * @return void
     */
    public function testNameIsTheConfiguredConnection(): void
    {
        $this->setConnectionSetting('identity');

        self::assertSame('identity', AuthorizationConnection::name());
    }

    /**
     * The resolved connection is the configured one, else the instance's own,
     * else the application's default.
     *
     * @return void
     */
    public function testResolveFallsBackToTheInstanceThenTheDefault(): void
    {
        $this->setConnectionSetting(null);

        self::assertSame('testing', AuthorizationConnection::resolve());
        self::assertSame('other', AuthorizationConnection::resolve('other'));

        $this->setConnectionSetting('identity');

        self::assertSame('identity', AuthorizationConnection::resolve());
        self::assertSame('identity', AuthorizationConnection::resolve('other'));
    }

    /**
     * The connection the package's pivots and transactions use is the
     * configured connection, else the application's default.
     *
     * @return void
     */
    public function testConnectionIsTheConfiguredConnectionElseTheDefault(): void
    {
        self::assertSame(DB::connection(), AuthorizationConnection::connection());

        $this->useAnAuthorizationConnection();

        self::assertSame(self::authorizationConnection(), AuthorizationConnection::connection());
    }

    /**
     * The shipped migrations create every package table on the configured
     * connection.
     *
     * @return void
     */
    public function testMigrationsCreateTheTablesOnTheConfiguredConnection(): void
    {
        $this->useAnAuthorizationConnection();

        $schema = self::authorizationConnection()->getSchemaBuilder();

        foreach (self::TABLES as $table) {
            self::assertTrue($schema->hasTable($table), $table);
        }
    }

    /**
     * The shipped migrations drop every package table from the configured
     * connection and leave the default connection's tables alone.
     *
     * @return void
     */
    public function testMigrationsDropTheTablesFromTheConfiguredConnection(): void
    {
        $this->useAnAuthorizationConnection();
        $this->reversePackageMigrations();

        $schema = self::authorizationConnection()->getSchemaBuilder();

        foreach (self::TABLES as $table) {
            self::assertFalse($schema->hasTable($table), $table);
            self::assertTrue(DB::connection()->getSchemaBuilder()->hasTable($table), $table);
        }
    }

    /**
     * The models write their rows on the configured connection and read them
     * back from it, and none reaches the default connection.
     *
     * @return void
     */
    public function testModelsReadAndWriteOnTheConfiguredConnection(): void
    {
        $this->useAnAuthorizationConnection();

        Role::create(['name' => 'editor']);
        Permission::create(['name' => 'posts:edit']);
        Policy::create(['name' => 'readers', 'document' => ['version' => 1, 'statements' => []]]);

        self::assertSame('editor', Role::query()->sole()->name);
        self::assertSame('posts:edit', Permission::query()->sole()->name);
        self::assertSame('readers', Policy::query()->sole()->name);

        foreach (['roles', 'permissions', 'policies'] as $table) {
            self::assertSame(1, self::authorizationConnection()->table($table)->count(), $table);
            self::assertSame(0, DB::connection()->table($table)->count(), $table);
        }
    }

    /**
     * The pivots write their rows on the configured connection, although the
     * grantee lives on the default connection, and the grants read back through
     * the grantee's relations.
     *
     * @return void
     */
    public function testPivotsReadAndWriteOnTheConfiguredConnection(): void
    {
        $this->useAnAuthorizationConnection();

        $role       = Role::create(['name' => 'editor']);
        $permission = Permission::create(['name' => 'posts:edit']);
        $policy     = Policy::create(['name' => 'readers', 'document' => ['version' => 1, 'statements' => []]]);

        $role->permissions()->attach($permission);

        $identity = StubIdentity::create(['id' => 'b3c1a9de-6f43-4d0e-9a52-0d0d6cf0c001']);
        $identity->assignRole($role);
        $identity->givePermission($permission);
        $identity->attachPolicy($policy);

        foreach (['role_permissions', 'authorizable_roles', 'authorizable_permissions', 'authorizable_policies'] as $table) {
            self::assertSame(1, self::authorizationConnection()->table($table)->count(), $table);
            self::assertSame(0, DB::connection()->table($table)->count(), $table);
        }

        $fresh = StubIdentity::query()->findOrFail('b3c1a9de-6f43-4d0e-9a52-0d0d6cf0c001');

        self::assertSame(['editor'], $fresh->roles->pluck('name')->all());
        self::assertSame(['posts:edit'], $fresh->permissions->pluck('name')->all());
        self::assertSame(['readers'], $fresh->policies->pluck('name')->all());
        self::assertSame(['posts:edit'], $role->permissions()->pluck('name')->all());
    }

    /**
     * With the setting unset, a grantee on another connection reads and writes
     * its grants on the application's default connection, where the migrations
     * created the package's tables, not on its own.
     *
     * @return void
     */
    public function testGrantsStayOnTheDefaultConnectionForAGranteeOnAnotherConnection(): void
    {
        $this->setConnectionSetting(null);
        $this->createIdentitiesConnection();

        $role       = Role::create(['name' => 'editor']);
        $permission = Permission::create(['name' => 'posts:edit']);
        $policy     = Policy::create(['name' => 'readers', 'document' => ['version' => 1, 'statements' => []]]);

        $identity = new StubIdentity(['id' => 'b3c1a9de-6f43-4d0e-9a52-0d0d6cf0c002']);
        $identity->setConnection('identities');
        $identity->save();

        $identity->assignRole($role);
        $identity->givePermission($permission);
        $identity->attachPolicy($policy);

        foreach (['authorizable_roles', 'authorizable_permissions', 'authorizable_policies'] as $table) {
            self::assertSame(1, DB::connection()->table($table)->count(), $table);
            self::assertFalse(DB::connection('identities')->getSchemaBuilder()->hasTable($table), $table);
        }

        /** @var \Tests\Feature\Stubs\StubIdentity $fresh */
        $fresh = StubIdentity::on('identities')->findOrFail('b3c1a9de-6f43-4d0e-9a52-0d0d6cf0c002');

        self::assertTrue($fresh->hasRole('editor'));
        self::assertSame(['posts:edit'], $fresh->permissions->pluck('name')->all());
        self::assertSame(['readers'], $fresh->policies->pluck('name')->all());

        $fresh->revokeRole('editor');

        self::assertSame(0, DB::connection()->table('authorizable_roles')->count());
    }

    /**
     * Register a second in-memory SQLite connection holding only the stub
     * identities table, for a grantee that lives apart from the package's
     * tables.
     *
     * @return void
     */
    private function createIdentitiesConnection(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app?->make(Repository::class);

        $config->set('database.connections.identities', [
            'driver'   => 'sqlite',
            'database' => ':memory:',
            'prefix'   => '',
        ]);

        DB::connection('identities')->getSchemaBuilder()->create('stub_identities', static function (Blueprint $table): void {
            $table->string('id')->primary();
            $table->string('name')->nullable();
            $table->timestamps();
        });
    }

    /**
     * Set the `authorization.connection` setting.
     *
     * @param  mixed  $value
     * @return void
     */
    private function setConnectionSetting(mixed $value): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app?->make(Repository::class);

        $config->set('authorization.connection', $value);
    }
}
