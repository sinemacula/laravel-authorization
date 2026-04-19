<?php

/**
 * Add the `parent_id` column to the `roles` table.
 *
 * Introduces a self-referential foreign key that enables role hierarchy /
 * inheritance. A child role inherits all permissions from its ancestors
 * when `authorization.hierarchy.enabled` is true. Null `parent_id`
 * marks the role as a root (no parent). ON DELETE SET NULL promotes
 * children to root when a parent role is removed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
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
        $table = config('authorization.tables.roles', 'roles');

        Schema::table($table, static function (Blueprint $blueprint) use ($table): void {
            $blueprint->uuid('parent_id')->nullable()->after('is_system');
            $blueprint->index('parent_id', $table . '_parent_id_index');
        });

        // Self-referential FK added in a separate statement so SQLite's
        // table-rebuild logic (used for ALTER TABLE) does not trip over the
        // column referencing itself during the same DDL batch that creates it.
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

        if (DB::getDriverName() !== 'sqlite') {
            Schema::table($table, static function (Blueprint $blueprint): void {
                $blueprint->dropForeign(['parent_id']);
            });
        }

        Schema::table($table, static function (Blueprint $blueprint) use ($table): void {
            $blueprint->dropIndex($table . '_parent_id_index');
            $blueprint->dropColumn('parent_id');
        });
    }
};
