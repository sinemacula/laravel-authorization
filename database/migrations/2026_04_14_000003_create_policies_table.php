<?php

/**
 * Create the `policies` table.
 *
 * Policies are JSON documents of allow and deny statements attached to
 * authorizable identities.
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
        $table  = config('authorization.tables.policies', 'policies');
        $schema = Schema::connection($this->getConnection());

        (new MigrationCollisionGuard($schema))->ensureNotExists($table);

        $schema->create($table, static function (Blueprint $blueprint): void {
            $blueprint->uuid('id')->primary();
            $blueprint->string('name')->unique();
            $blueprint->string('description')->nullable();

            // Platform-protection marker. Policies flagged system refuse delete
            // and every edit, clearing this flag included, unless the
            // model-layer `forceSystem()` escape hatch is invoked, so a
            // platform-shipped `break-glass` policy cannot be casually removed
            // or changed by a caller with raw Eloquent access.
            $blueprint->boolean('is_system')->default(false);

            $blueprint->json('document');
            $blueprint->timestamps();
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
        $table = config('authorization.tables.policies', 'policies');

        Schema::connection($this->getConnection())->dropIfExists($table);
    }
};
