<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Authorization\Database\MigrationCollisionGuard;

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

        (new MigrationCollisionGuard(Schema::getConnection()->getSchemaBuilder()))->ensureNotExists($table);

        Schema::create($table, static function (Blueprint $table): void {

            $table->uuid('id')->primary();
            $table->string('name');
            $table->string('guard_name')->nullable();
            $table->string('description')->nullable();

            // Platform-protection marker. Roles flagged system refuse delete /
            // rename unless the model-layer `forceSystem()` escape hatch is
            // invoked, so a platform-shipped `super-admin` cannot be casually
            // removed by a caller with raw Eloquent access.
            $table->boolean('is_system')->default(false);
            $table->timestamps();

            // Explicit lookup index on `(name, guard_name)`. Every
            // `resolveRole()` / `hasRole()` query filters on both columns; most
            // engines back unique constraints with an index already but older
            // MySQL storage  engines and some managed databases do not. The
            // explicit declaration is belt-and-braces insurance for the hot
            // path.
            $table->index(['name', 'guard_name'], 'roles_name_guard_index');
        });

        // Functional unique index on `(name, COALESCE(guard_name, ''))`.
        // Ordinary UNIQUE(name, guard_name) would permit duplicate
        // guard-agnostic rows because MySQL, PostgreSQL and SQLite all treat
        // NULL as distinct inside unique indexes. COALESCE folds nulls to the
        // empty string so the invariant "at most one row per (name, guard)
        // pair, including the null-guard slot" is enforced at the data layer.
        DB::statement(
            sprintf(
                'CREATE UNIQUE INDEX %s_name_guard_unique ON %s (name, (COALESCE(guard_name, \'\')))',
                $table,
                $table,
            ),
        );
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
