<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Authorization\Database\MigrationCollisionGuard;

/**
 * Create the `authorizable_roles` polymorphic pivot table.
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
        $table = config('authorization.tables.authorizable_roles', 'authorizable_roles');

        /** @var string $rolesTable */
        $rolesTable = config('authorization.tables.roles', 'roles');

        MigrationCollisionGuard::ensureNotExists($table);

        Schema::create($table, static function (Blueprint $table) use ($rolesTable): void {

            $table->uuid('role_id');
            $table->string('authorizable_type');
            $table->string('authorizable_id');

            // Optional expiry for temporal grants — null means "forever". Rows
            // whose `expires_at` is in the past are filtered out of the
            // relation on read; pruning the expired rows is a
            // consumer-scheduled task. The authorization package does not ship
            // a sweeper in v1.0.0.
            $table->timestamp('expires_at')->nullable();

            $table->unique(['role_id', 'authorizable_type', 'authorizable_id'], 'authorizable_roles_unique');
            $table->index(['authorizable_type', 'authorizable_id'], 'authorizable_roles_morph_index');
            $table->index('expires_at', 'authorizable_roles_expires_at_index');

            $table->foreign('role_id')->references('id')->on($rolesTable)->cascadeOnDelete();
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
        $table = config('authorization.tables.authorizable_roles', 'authorizable_roles');

        Schema::dropIfExists($table);
    }
};
