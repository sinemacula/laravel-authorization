<?php

/**
 * Create the `role_permissions` pivot table.
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
        $table = config('authorization.tables.role_permissions', 'role_permissions');
        /** @var string $rolesTable */
        $rolesTable = config('authorization.tables.roles', 'roles');
        /** @var string $permissionsTable */
        $permissionsTable = config('authorization.tables.permissions', 'permissions');

        $schema = Schema::connection($this->getConnection());

        (new MigrationCollisionGuard($schema))->ensureNotExists($table);

        $schema->create($table, static function (Blueprint $blueprint) use ($table, $rolesTable, $permissionsTable): void {
            $blueprint->uuid('role_id');
            $blueprint->uuid('permission_id');

            // When the role stops carrying the permission, in UTC; null for
            // forever. Rows whose expiry has passed no longer count, and are
            // left for `authorization:prune` to remove. A `dateTime` rather
            // than a `timestamp`, which stops at 2038 on MySQL.
            $blueprint->dateTime('expires_at')->nullable();

            $blueprint->primary(['role_id', 'permission_id']);
            $blueprint->index('expires_at', $table . '_expires_at_index');

            $blueprint->foreign('role_id')->references('id')->on($rolesTable)->cascadeOnDelete();
            $blueprint->foreign('permission_id')->references('id')->on($permissionsTable)->cascadeOnDelete();
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
        $table = config('authorization.tables.role_permissions', 'role_permissions');

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
