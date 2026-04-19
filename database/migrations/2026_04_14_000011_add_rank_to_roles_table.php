<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Add the `rank` column to the `roles` table.
 *
 * Introduces a nullable integer rank that models role seniority.
 * Lower values denote more senior roles (0 is the most senior,
 * mirroring IAM conventions). Null means "unranked" — the role is
 * not subject to rank-based checks, making the feature opt-in per
 * role and imposing no complexity on simple consumers.
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

        Schema::table($table, static function (Blueprint $blueprint) use ($table): void {
            $blueprint->integer('rank')->nullable()->after('parent_id');
            $blueprint->index('rank', $table . '_rank_index');
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
        $table = config('authorization.tables.roles', 'roles');

        Schema::table($table, static function (Blueprint $blueprint) use ($table): void {
            $blueprint->dropIndex($table . '_rank_index');
            $blueprint->dropColumn('rank');
        });
    }
};
