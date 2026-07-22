<?php

/**
 * Add nullable polymorphic tenant columns to the `permissions` table.
 *
 * Introduces `tenant_type` and `tenant_id` to support row-level multi-tenant
 * permission ownership. When both columns are null the permission is global
 * (platform-level); a concrete value pair marks the permission as tenant-owned,
 * scoping it to a specific tenant entity.
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

        Schema::table($table, static function (Blueprint $blueprint) use ($table): void {
            $blueprint->string('tenant_type')->nullable()->after('is_system');
            $blueprint->string('tenant_id')->nullable()->after('tenant_type');
            $blueprint->index(['tenant_type', 'tenant_id'], $table . '_tenant_index');
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

        Schema::table($table, static function (Blueprint $blueprint) use ($table): void {
            $blueprint->dropIndex($table . '_tenant_index');
            $blueprint->dropColumn(['tenant_type', 'tenant_id']);
        });
    }
};
