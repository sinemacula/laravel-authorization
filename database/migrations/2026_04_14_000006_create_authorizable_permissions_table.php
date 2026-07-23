<?php

/**
 * Create the `authorizable_permissions` polymorphic pivot table.
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
        $table = config('authorization.tables.authorizable_permissions', 'authorizable_permissions');
        /** @var string $permissionsTable */
        $permissionsTable = config('authorization.tables.permissions', 'permissions');

        MigrationCollisionGuard::ensureNotExists($table);

        Schema::create($table, static function (Blueprint $table) use ($permissionsTable): void {
            $table->uuid('permission_id');
            $table->string('authorizable_type');
            $table->string('authorizable_id');

            // Optional expiry for temporal grants — null means "forever". Rows
            // whose `expires_at` is in the past are filtered out of the
            // relation on read.
            $table->timestamp('expires_at')->nullable();

            $table->unique(['permission_id', 'authorizable_type', 'authorizable_id'], 'authorizable_permissions_unique');
            $table->index(['authorizable_type', 'authorizable_id'], 'authorizable_permissions_morph_index');
            $table->index('expires_at', 'authorizable_permissions_expires_at_index');

            $table->foreign('permission_id')->references('id')->on($permissionsTable)->cascadeOnDelete();
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
        $table = config('authorization.tables.authorizable_permissions', 'authorizable_permissions');

        Schema::dropIfExists($table);
    }
};
