<?php

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

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
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
        $table  = config('authorization.tables.roles', 'roles');
        $schema = Schema::connection($this->getConnection());

        (new MigrationCollisionGuard($schema))->ensureNotExists($table);

        $schema->create($table, static function (Blueprint $blueprint) use ($table): void {
            $blueprint->uuid('id');
            $blueprint->string('name');
            $blueprint->string('guard')->nullable();
            $blueprint->string('description')->nullable();

            // Platform-protection marker. Roles flagged system refuse delete
            // and every edit, clearing this flag included, unless the
            // model-layer `forceSystem()` escape hatch is invoked, so a
            // platform-shipped `super-admin` cannot be casually removed or
            // changed by a caller with raw Eloquent access.
            $blueprint->boolean('is_system')->default(false);

            // The parent role, for role hierarchy. A child role inherits every
            // permission of its ancestors when
            // `authorization.hierarchy.enabled` is true. Null marks the role as
            // a root. Deleting a parent promotes its children to roots.
            $blueprint->uuid('parent_id')->nullable();

            // Role seniority. Lower values denote more senior roles (0 is the
            // most senior, mirroring IAM conventions). Null means "unranked":
            // the role is not subject to rank-based checks, so the feature is
            // opt-in per role.
            $blueprint->integer('rank')->nullable();

            // The tenant that owns the role. Both columns null mark the role as
            // platform-wide; a concrete pair marks it as owned by that tenant.
            $blueprint->string('tenant_type')->nullable();
            $blueprint->string('tenant_id')->nullable();

            $blueprint->timestamps();

            // The primary key is declared as a command rather than on the
            // column, so it is created before the self-referencing key below
            // that needs it: a key declared on the column is only added after
            // every declared command.
            $blueprint->primary('id');

            // Explicit lookup index on `(name, guard)`. Every `resolveRole()` /
            // `hasRole()` query filters on both columns; most engines back
            // unique constraints with an index already but older MySQL storage
            // engines and some managed databases do not. The explicit
            // declaration is belt-and-braces insurance for the hot path.
            $blueprint->index(['name', 'guard'], $table . '_name_guard_index');
            $blueprint->index('parent_id', $table . '_parent_id_index');
            $blueprint->index('rank', $table . '_rank_index');
            $blueprint->index(['tenant_type', 'tenant_id'], $table . '_tenant_index');

            // The self-referencing key is declared with the table, so it holds
            // on every database, SQLite included.
            $blueprint->foreign('parent_id')->references('id')->on($table)->nullOnDelete();
        });

        // Functional unique index on `(name, COALESCE(guard, ''))`. Ordinary
        // UNIQUE(name, guard) would permit duplicate guard-agnostic rows
        // because MySQL, PostgreSQL and SQLite all treat NULL as distinct
        // inside unique indexes. COALESCE folds nulls to the empty string so
        // the invariant "at most one row per (name, guard) pair, including the
        // null-guard slot" is enforced at the data layer.
        $schema->getConnection()->statement(sprintf(
            'CREATE UNIQUE INDEX %s_name_guard_unique ON %s (name, (COALESCE(guard, \'\')))',
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
        $table = config('authorization.tables.roles', 'roles');

        Schema::connection($this->getConnection())->dropIfExists($table);
    }

    /**
     * The connection the table lives on, the one the package's models read and
     * write it on: `authorization.connection`, or the default when unset.
     *
     * @return string|null
     */
    #[Override]
    public function getConnection(): ?string
    {
        return AuthorizationConnection::name();
    }
};
