<?php

/**
 * Create the `permissions` table.
 *
 * Permissions are atomic action strings that can be granted directly to an
 * identity or inherited via a role. The `guard_name` column is nullable: a null
 * value marks the permission as guard-agnostic (applies to every guard), a
 * concrete string scopes it to a single guard.
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
        $table  = config('authorization.tables.permissions', 'permissions');
        $schema = Schema::connection($this->getConnection());

        (new MigrationCollisionGuard($schema))->ensureNotExists($table);

        $schema->create($table, static function (Blueprint $blueprint) use ($table): void {
            $blueprint->uuid('id')->primary();
            $blueprint->string('name');
            $blueprint->string('guard_name')->nullable();
            $blueprint->string('description')->nullable();

            // Optional grouping key for admin UIs. Nullable so categorisation
            // is opt-in.
            $blueprint->string('category')->nullable();

            // Platform-protection marker. Permissions flagged system refuse
            // delete and every edit, clearing this flag included, unless the
            // model-layer `forceSystem()` escape hatch is invoked, so a
            // platform-shipped `*` super-admin permission cannot be casually
            // removed or changed by a caller with raw Eloquent access.
            $blueprint->boolean('is_system')->default(false);

            // The tenant that owns the permission. Both columns null mark the
            // permission as platform-wide; a concrete pair marks it as owned by
            // that tenant.
            $blueprint->string('tenant_type')->nullable();
            $blueprint->string('tenant_id')->nullable();

            $blueprint->timestamps();

            // Explicit lookup index on `(name, guard_name)`. Every
            // `resolvePermission()` / `hasPermission()` query filters on both
            // columns; most engines back unique constraints with an index
            // already but older MySQL storage engines and some managed
            // databases do not. The explicit declaration is belt-and-braces
            // insurance for the hot path.
            $blueprint->index(['name', 'guard_name'], $table . '_name_guard_index');
            $blueprint->index(['tenant_type', 'tenant_id'], $table . '_tenant_index');
        });

        // Functional unique index on `(name, COALESCE(guard_name, ''))`.
        // Ordinary UNIQUE(name, guard_name) would permit duplicate
        // guard-agnostic rows because MySQL, PostgreSQL and SQLite all treat
        // NULL as distinct inside unique indexes. COALESCE folds nulls to the
        // empty string so the invariant "at most one row per (name, guard)
        // pair, including the null-guard slot" is enforced at the data layer.
        $schema->getConnection()->statement(sprintf(
            'CREATE UNIQUE INDEX %s_name_guard_unique ON %s (name, (COALESCE(guard_name, \'\')))',
            $table,
            $table,
        ));
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

        Schema::connection($this->getConnection())->dropIfExists($table);
    }
};
