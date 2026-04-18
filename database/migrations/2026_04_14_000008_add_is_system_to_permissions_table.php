<?php

/**
 * Add the `is_system` column to the `permissions` table.
 *
 * Mirrors the platform-protection marker that ships on the `roles`
 * table: a permission flagged system refuses delete / rename unless
 * the model-layer `forceSystem()` escape hatch is invoked, so a
 * platform-shipped `*:*` super-admin permission cannot be casually
 * removed by a caller with raw Eloquent access.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

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

        Schema::table($table, static function (Blueprint $table): void {
            // Platform-protection marker. Permissions flagged
            // system refuse delete / rename unless the model-layer
            // `forceSystem()` escape hatch is invoked.
            $table->boolean('is_system')->default(false)->after('description');
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
        $table = config('authorization.tables.permissions', 'permissions');

        Schema::table($table, static function (Blueprint $table): void {
            $table->dropColumn('is_system');
        });
    }
};
