<?php

/**
 * Create the `permissions` table.
 *
 * Permissions are atomic action strings that can be granted directly
 * to an identity or inherited via a role. The `guard_name` column is
 * nullable: a null value marks the permission as guard-agnostic
 * (applies to every guard), a concrete string scopes it to a single
 * guard.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Authorization\Database\MigrationCollisionGuard;

return new class extends Migration {
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up(): void
    {
        /** @var string $table */
        $table = config('authorization.tables.permissions', 'permissions');

        MigrationCollisionGuard::ensureNotExists($table);

        Schema::create($table, static function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->string('name');
            $table->string('guard_name')->nullable();
            $table->string('description')->nullable();
            $table->timestamps();

            $table->unique(['name', 'guard_name']);
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down(): void
    {
        /** @var string $table */
        $table = config('authorization.tables.permissions', 'permissions');

        Schema::dropIfExists($table);
    }
};
