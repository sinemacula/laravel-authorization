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
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
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

        $schema = Schema::connection($this->getConnection());

        (new MigrationCollisionGuard($schema))->ensureNotExists($table);

        $schema->create($table, static function (Blueprint $blueprint) use ($policiesTable): void {
            $blueprint->uuid('policy_id');
            $blueprint->string('authorizable_type');
            $blueprint->string('authorizable_id');

            // Optional expiry for temporal grants — null means "forever". Rows
            // whose `expires_at` is in the past are filtered out of the
            // relation on read.
            $blueprint->timestamp('expires_at')->nullable();

            $blueprint->unique(['policy_id', 'authorizable_type', 'authorizable_id'], 'authorizable_policies_unique');
            $blueprint->index(['authorizable_type', 'authorizable_id'], 'authorizable_policies_morph_index');
            $blueprint->index('expires_at', 'authorizable_policies_expires_at_index');

            $blueprint->foreign('policy_id')->references('id')->on($policiesTable)->cascadeOnDelete();
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

        Schema::connection($this->getConnection())->dropIfExists($table);
    }

    /**
     * The connection the table lives on, the one the package's models read and
     * write it on: `authorization.connection`, or the default when unset.
     *
     * @return string|null
     */
    #[Override]
    public function getConnection(): ?string
    {
        return AuthorizationConnection::name();
    }
};
