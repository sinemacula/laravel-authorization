<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Database\MigrationCollisionException;
use SineMacula\Laravel\Authorization\Database\MigrationCollisionGuard;
use Tests\TestCase;

/**
 * Coverage for the shipped migration collision guard. Published
 * migrations invoke the guard before creating their table so a
 * matrix run against a persistent database cannot silently
 * collide with an unrelated table of the same name.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MigrationCollisionGuard::class)]
#[CoversClass(MigrationCollisionException::class)]
final class MigrationCollisionGuardTest extends TestCase
{
    /**
     * When the table already exists, the guard raises the typed
     * collision exception and the migration aborts.
     *
     * @return void
     */
    public function testThrowsWhenTargetTableAlreadyExists(): void
    {
        Schema::create('collision_guard_probe', static function (Blueprint $table): void {
            $table->id();
        });

        $this->expectException(MigrationCollisionException::class);

        MigrationCollisionGuard::ensureNotExists('collision_guard_probe');
    }
}
