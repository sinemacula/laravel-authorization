<?php

/**
 * Create the `authorizable_policies` polymorphic pivot table.
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
        $table = config('authorization.tables.authorizable_policies', 'authorizable_policies');
        /** @var string $policiesTable */
        $policiesTable = config('authorization.tables.policies', 'policies');

        MigrationCollisionGuard::ensureNotExists($table);

        Schema::create($table, static function (Blueprint $table) use ($policiesTable): void {
            $table->ulid('policy_id');
            $table->string('authorizable_type');
            $table->string('authorizable_id');

            $table->unique(['policy_id', 'authorizable_type', 'authorizable_id'], 'authorizable_policies_unique');
            $table->index(['authorizable_type', 'authorizable_id'], 'authorizable_policies_morph_index');

            $table->foreign('policy_id')->references('id')->on($policiesTable)->cascadeOnDelete();
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
        $table = config('authorization.tables.authorizable_policies', 'authorizable_policies');

        Schema::dropIfExists($table);
    }
};
