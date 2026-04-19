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
use Illuminate\Support\Facades\DB;
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

            // Explicit lookup index on `(name, guard_name)`. Every
            // `resolvePermission()` / `hasPermission()` query filters on both
            // columns; most engines back unique constraints with an index
            // already but older MySQL storage engines and some managed
            // databases do not. The explicit declaration is belt-and-braces
            // insurance for the hot path.
            $table->index(['name', 'guard_name'], 'permissions_name_guard_index');
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
        $table = config('authorization.tables.permissions', 'permissions');

        Schema::dropIfExists($table);
    }
};
