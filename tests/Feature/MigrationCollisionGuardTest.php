<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Schema\Builder;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Database\MigrationCollisionException;
use SineMacula\Laravel\Authorization\Database\MigrationCollisionGuard;
use Tests\TestCase;

/**
 * Coverage for the shipped migration collision guard. Published migrations
 * invoke the guard before creating their table so a matrix run against a
 * persistent database cannot silently collide with an unrelated table of the
 * same name. The guard asks the schema builder it is given, so it is exercised
 * against a real builder and against a fake one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(MigrationCollisionGuard::class)]
#[CoversClass(MigrationCollisionException::class)]
final class MigrationCollisionGuardTest extends TestCase
{
    /**
     * When the table already exists, the guard raises the typed collision
     * exception naming the table, and the migration aborts.
     *
     * @return void
     */
    public function testThrowsWhenTargetTableAlreadyExists(): void
    {
        Schema::create('collision_guard_probe', static function (Blueprint $table): void {
            $table->id();
        });

        $guard = new MigrationCollisionGuard(Schema::connection(null));

        try {
            $guard->ensureNotExists('collision_guard_probe');
            self::fail('Expected the guard to refuse an existing table.');
        } catch (MigrationCollisionException $exception) {
            self::assertSame('collision_guard_probe', $exception->getTable());
        }
    }

    /**
     * When no table of the name exists, the guard lets the migration proceed.
     *
     * @return void
     */
    public function testPassesWhenTargetTableDoesNotExist(): void
    {
        $guard = new MigrationCollisionGuard(Schema::connection(null));

        $guard->ensureNotExists('collision_guard_absent');

        self::assertFalse(Schema::hasTable('collision_guard_absent'));
    }

    /**
     * The guard asks the builder it was given, not the default connection: a
     * builder that reports the table refuses it although the default connection
     * has no such table.
     *
     * @return void
     */
    public function testAsksTheGivenBuilderWhetherTheTableExists(): void
    {
        $schema = \Mockery::mock(Builder::class);
        $schema->shouldReceive('hasTable')->once()->with('collision_guard_fake')->andReturn(true);

        $this->expectException(MigrationCollisionException::class);
        $this->expectExceptionMessage('Table \'collision_guard_fake\' already exists');

        (new MigrationCollisionGuard($schema))->ensureNotExists('collision_guard_fake');
    }

    /**
     * A builder that reports no table lets the migration proceed, after asking
     * exactly once for the named table.
     *
     * @return void
     */
    public function testPassesWhenTheGivenBuilderHasNoSuchTable(): void
    {
        $schema = \Mockery::mock(Builder::class);
        $schema->shouldReceive('hasTable')->once()->with('collision_guard_fake')->andReturn(false);

        (new MigrationCollisionGuard($schema))->ensureNotExists('collision_guard_fake');

        self::assertSame(1, \Mockery::getContainer()->mockery_getExpectationCount());
    }
}
