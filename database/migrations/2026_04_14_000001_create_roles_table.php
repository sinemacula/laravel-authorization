<?php

/**
 * Create the `roles` table.
 *
 * Roles are named buckets of permissions shared across authorizable
 * identities. The `guard_name` column is nullable: a null value marks
 * the role as guard-agnostic (applies to every guard), a concrete
 * string scopes the role to a single guard and mirrors Spatie's
 * `laravel-permission` convention for migrating consumers.
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
        $table = config('authorization.tables.roles', 'roles');

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
        $table = config('authorization.tables.roles', 'roles');

        Schema::dropIfExists($table);
    }
};
