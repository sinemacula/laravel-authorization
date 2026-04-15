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
            $table->ulid('permission_id');
            $table->string('authorizable_type');
            $table->string('authorizable_id');

            $table->unique(['permission_id', 'authorizable_type', 'authorizable_id'], 'authorizable_permissions_unique');
            $table->index(['authorizable_type', 'authorizable_id'], 'authorizable_permissions_morph_index');

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
