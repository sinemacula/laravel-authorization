<?php

declare(strict_types = 1);

namespace Tests\Feature\Services;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Exceptions\ReservedRoleNameException;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\Support\RecordWriter;
use Tests\Concerns\UsesAnAuthorizationConnection;
use Tests\TestCase;

/**
 * Feature tests for `RecordWriter`, which saves and deletes rows for the record
 * services in one transaction on the package's connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecordWriter::class)]
final class RecordWriterTest extends TestCase
{
    use UsesAnAuthorizationConnection;

    /**
     * The row is looked up and saved inside one transaction on the package's
     * connection, with the given attributes.
     *
     * @return void
     */
    public function testSavesInsideATransactionOnThePackageConnection(): void
    {
        $this->useAnAuthorizationConnection();

        $base  = self::authorizationConnection()->transactionLevel();
        $level = null;

        $role = RecordWriter::save(static function () use (&$level): Role {
            $level = self::authorizationConnection()->transactionLevel();

            return new Role;
        }, ['name' => 'editor', 'rank' => 2]);

        self::assertSame($base + 1, $level);
        self::assertTrue($role->exists);
        self::assertSame(['editor', 2], [$role->name, $role->rank]);
        self::assertSame(1, self::authorizationConnection()->table('roles')->where('name', 'editor')->count());
    }

    /**
     * A save the model refuses writes nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefusedSaveWritesNothing(): void
    {
        Role::query()->create(['name' => 'admin', 'is_system' => true]);

        try {
            RecordWriter::save(static fn (): Role => new Role, ['name' => 'admin', 'tenant_type' => 'stub_tenant', 'tenant_id' => 'tenant-a']);
            self::fail('The save was not refused.');
        } catch (ReservedRoleNameException) {
            self::assertSame(1, DB::table('roles')->count());
        }
    }

    /**
     * The row is looked up and deleted inside one transaction.
     *
     * @return void
     */
    public function testDeletesInsideATransaction(): void
    {
        $role  = Role::query()->create(['name' => 'editor']);
        $base  = DB::connection()->transactionLevel();
        $level = null;

        RecordWriter::delete(static function () use (&$level, $role): Role {
            $level = DB::connection()->transactionLevel();

            return $role;
        });

        self::assertSame($base + 1, $level);
        self::assertSame(0, Role::query()->count());
    }
}
