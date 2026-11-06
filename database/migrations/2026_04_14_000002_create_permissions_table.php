<?php

/**
 * Create the `permissions` table.
 *
 * Permissions are atomic action strings that can be granted directly to an
 * identity or inherited via a role. The `guard` column is nullable: a null
 * value marks the permission as guard-agnostic (applies to every guard), a
 * concrete string scopes it to a single guard. A permission is owned by the
 * platform (null tenant columns) or by one tenant, and its name is unique
 * within its owner and guard.
 *
 * The tenant columns compare their exact bytes on every database: on MySQL they
 * are collated `utf8mb4_0900_bin`, which neither folds case nor pads trailing
 * spaces (`ExactReferences`), so a tenant whose key differs from another's only
 * by case or a trailing space is a different one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Database\ExactReferences;
use SineMacula\Laravel\Authorization\Database\MigrationCollisionGuard;
use SineMacula\Laravel\Authorization\Database\NullFoldingUniqueIndex;

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

        $exact = new ExactReferences($schema->getConnection());

        $schema->create($table, static function (Blueprint $blueprint) use ($table, $exact): void {
            $blueprint->uuid('id')->primary();

            // Names, tenant types and tenant ids are bounded to 191 characters
            // and guards to 64, so the unique key below stays within MySQL's
            // 3072-byte InnoDB key limit under `utf8mb4`.
            $blueprint->string('name', 191);
            $blueprint->string('guard', 64)->nullable();
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
            $blueprint->string('tenant_type', 191)->nullable();
            $blueprint->string('tenant_id', 191)->nullable();

            $blueprint->timestamps();

            // Explicit lookup index on `(name, guard)`. Every
            // `resolvePermission()` / `hasPermission()` query filters on both
            // columns. The unique key below can serve the `name` prefix but not
            // the `guard` comparison, since it stores `COALESCE(guard, '')`, so
            // this index serves the two-column lookup.
            $blueprint->index(['name', 'guard'], $table . '_name_guard_index');
            $blueprint->index(['tenant_type', 'tenant_id'], $table . '_tenant_index');

            // On MySQL the reference columns compare their exact bytes, as on
            // the other databases.
            $exact->apply($blueprint);
        });

        // A name is unique within its owner and guard: at most one row per
        // name, guard and tenant, with a null guard (guard-agnostic) and null
        // tenant columns (platform-wide) each counting as one value. A platform
        // permission and a tenant's permission may share a name and guard, and
        // two tenants may each have their own.
        (new NullFoldingUniqueIndex($schema->getConnection()))->create(
            $table,
            $table . '_name_guard_owner_unique',
            ['name'],
            ['guard', 'tenant_type', 'tenant_id'],
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
