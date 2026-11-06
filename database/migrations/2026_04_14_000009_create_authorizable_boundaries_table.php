<?php

/**
 * Create the `authorizable_boundaries` table: the permission boundaries of
 * authorizable grantees (AUTHZ-7.4).
 *
 * Each row sets one managed policy as one grantee's boundary within one scope:
 * platform-wide (null tenant columns) or one tenant, and that tenant's subtree
 * unless `include_subtree` is false. A grantee has at most one boundary per
 * scope; setting another replaces it. A policy set as a boundary cannot be
 * deleted until the boundary is removed.
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
use SineMacula\Laravel\Authorization\Database\NullFoldingUniqueIndex;

return new class extends Migration {
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up(): void
    {
        /** @var string $table */
        $table = config('authorization.tables.authorizable_boundaries', 'authorizable_boundaries');
        /** @var string $policiesTable */
        $policiesTable = config('authorization.tables.policies', 'policies');

        $schema = Schema::connection($this->getConnection());

        (new MigrationCollisionGuard($schema))->ensureNotExists($table);

        $schema->create($table, static function (Blueprint $blueprint) use ($table, $policiesTable): void {
            $blueprint->uuid('policy_id');

            // The grantee: a principal or an identity. References are bounded
            // to 191 characters, as the suite bounds them.
            $blueprint->string('authorizable_type', 191);
            $blueprint->string('authorizable_id', 191);

            // The scope: both tenant columns null set the boundary
            // platform-wide, a pair sets it within that tenant, and its subtree
            // unless `include_subtree` is false.
            $blueprint->string('tenant_type', 191)->nullable();
            $blueprint->string('tenant_id', 191)->nullable();
            $blueprint->boolean('include_subtree')->default(true);

            // Who set the boundary, when the caller names them.
            $blueprint->string('granted_by_type', 191)->nullable();
            $blueprint->string('granted_by_id', 191)->nullable();

            $blueprint->timestamps();

            $blueprint->index(['authorizable_type', 'authorizable_id'], $table . '_morph_index');
            $blueprint->index(['tenant_type', 'tenant_id'], $table . '_tenant_index');
            $blueprint->index('policy_id', $table . '_policy_index');

            // A policy in use as a boundary is never deleted from under it: the
            // policy observer refuses the delete first, and the key refuses one
            // made past the model.
            $blueprint->foreign('policy_id')->references('id')->on($policiesTable)->restrictOnDelete();
        });

        // A grantee has at most one boundary per scope, with null tenant
        // columns (platform-wide) counting as one value.
        (new NullFoldingUniqueIndex($schema->getConnection()))->createDigested(
            $table,
            $table . '_unique',
            ['authorizable_type', 'authorizable_id'],
            ['tenant_type', 'tenant_id'],
        );
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down(): void
    {
        /** @var string $table */
        $table = config('authorization.tables.authorizable_boundaries', 'authorizable_boundaries');

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
