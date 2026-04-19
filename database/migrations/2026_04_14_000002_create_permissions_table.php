<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Authorization\Database\MigrationCollisionGuard;

/**
 * Create the `permissions` table.
 *
 * Permissions are atomic action strings that can be granted directly
 * to an identity or inherited via a role. The `guard` column is
 * nullable: a null value marks the permission as guard-agnostic
 * (applies to every guard), a concrete string scopes it to a single
 * guard.
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
        $table = config('authorization.tables.permissions', 'permissions');

        (new MigrationCollisionGuard(Schema::getConnection()->getSchemaBuilder()))->ensureNotExists($table);

        Schema::create($table, static function (Blueprint $table): void {

            $table->uuid('id')->primary();
            $table->string('name');
            $table->string('guard')->nullable();
            $table->string('description')->nullable();

            // Optional grouping key for admin UIs. Nullable so categorisation
            // is opt-in and existing rows are unaffected.
            $table->string('category')->nullable();

            // Lifecycle marker for permissions retired by a sync pass. Null
            // means "live"; a concrete timestamp means "retired" — the
            // gate-evaluation hot path filters rows with
            // `WHERE deprecated_at IS NULL`, so the column is indexed.
            $table->timestamp('deprecated_at')->nullable()->index();

            // Platform-protection marker. Permissions flagged system refuse
            // delete / rename unless the model-layer `forceSystem()` escape
            // hatch is invoked, so a platform-shipped `*:*` super-admin
            // permission cannot be casually removed by a caller with raw
            // Eloquent access.
            $table->boolean('is_system')->default(false);

            // Polymorphic tenant ownership. When both columns are null the
            // permission is global (platform-level); a concrete value pair
            // marks the permission as tenant-owned, scoping it to a specific
            // tenant entity.
            $table->string('tenant_type')->nullable();
            $table->string('tenant_id')->nullable();

            $table->timestamps();

            // Explicit lookup index on `(name, guard)`. Every
            // `resolvePermission()` / `hasPermission()` query filters on both
            // columns; most engines back unique constraints with an index
            // already but older MySQL storage engines and some managed
            // databases do not. The explicit declaration is belt-and-braces
            // insurance for the hot path.
            $table->index(['name', 'guard'], 'permissions_name_guard_index');

            $table->index(['tenant_type', 'tenant_id'], 'permissions_tenant_index');
        });

        // Functional unique index on `(name, COALESCE(guard, ''))`. Ordinary
        // UNIQUE(name, guard) would permit duplicate guard-agnostic rows
        // because MySQL, PostgreSQL and SQLite all treat NULL as distinct
        // inside unique indexes. COALESCE folds nulls to the empty string so
        // the invariant "at most one row per (name, guard) pair, including the
        // null-guard slot" is enforced at the data layer.
        DB::statement(
            sprintf(
                'CREATE UNIQUE INDEX %s_name_guard_unique ON %s (name, (COALESCE(guard, \'\')))',
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
