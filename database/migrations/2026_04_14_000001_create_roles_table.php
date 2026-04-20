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
 * Roles are named buckets of permissions shared across authorizable identities.
 * The `guard` column is nullable: a null value marks the role as guard-agnostic
 * (applies to every guard), a concrete string scopes the role to a single guard
 * and mirrors Spatie's `laravel-permission` convention for migrating consumers.
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
            $table->string('guard')->nullable();
            $table->string('description')->nullable();

            // Platform-protection marker. Roles flagged system refuse delete /
            // rename unless the model-layer `forceSystem()` escape hatch is
            // invoked, so a platform-shipped `super-admin` cannot be casually
            // removed by a caller with raw Eloquent access.
            $table->boolean('is_system')->default(false);

            // Self-referential parent for role hierarchy / inheritance. A child
            // role inherits all permissions from its ancestors when
            // `authorization.hierarchy.enabled` is true. Null marks the role as
            // a root (no parent). The FK is added in a separate statement below
            // to keep SQLite's table-rebuild logic happy.
            $table->uuid('parent_id')->nullable();

            // Role seniority. Lower values denote more senior roles (0 is the
            // most senior, mirroring IAM conventions). Null means "unranked" —
            // the role is not subject to rank-based checks, making the feature
            // opt-in per role.
            $table->integer('rank')->nullable();

            // Polymorphic tenant ownership. When both columns are null the role
            // is global (platform-level); a concrete value pair marks the role
            // as tenant-owned, scoping it to a specific tenant entity.
            $table->string('tenant_type')->nullable();
            $table->string('tenant_id')->nullable();

            $table->timestamps();

            // Explicit lookup index on `(name, guard)`. Every `resolveRole()` /
            // `hasRole()` query filters on both columns; most engines back
            // unique constraints with an index already but older MySQL storage
            // engines and some managed databases do not. The explicit
            // declaration is belt-and-braces insurance for the hot path.
            $table->index(['name', 'guard'], 'roles_name_guard_index');

            $table->index('parent_id', 'roles_parent_id_index');
            $table->index('rank', 'roles_rank_index');
            $table->index(['tenant_type', 'tenant_id'], 'roles_tenant_index');
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

        // Self-referential FK added in a separate statement so SQLite's
        // table-rebuild logic (used for ALTER TABLE) does not trip over the
        // column referencing itself during the same DDL batch that creates it.
        // ON DELETE SET NULL promotes children to root when a parent role is
        // removed.
        if (DB::getDriverName() !== 'sqlite') {
            Schema::table($table, static function (Blueprint $blueprint) use ($table): void {
                $blueprint->foreign('parent_id')
                    ->references('id')
                    ->on($table)
                    ->nullOnDelete();
            });
        }
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
