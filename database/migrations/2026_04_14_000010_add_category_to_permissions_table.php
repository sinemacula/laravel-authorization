<?php

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Add the nullable `category` column to the `permissions` table.
 *
 * Gives admin UIs a first-class grouping key to `GROUP BY` when
 * rendering large permission catalogues. The column is nullable so
 * existing rows are unaffected and categorisation is opt-in.
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
        $table = config('authorization.tables.permissions', 'permissions');

        Schema::table($table, static function (Blueprint $table): void {
            // Optional grouping key for admin UIs. Nullable so categorisation
            // is opt-in and existing rows are unaffected.
            $table->string('category')->nullable()->after('description');
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
            $table->dropColumn('category');
        });
    }
};
