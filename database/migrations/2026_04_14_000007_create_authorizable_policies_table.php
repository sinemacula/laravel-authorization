<?php

/**
 * Create the `authorizable_policies` table: policies attached to authorizable
 * identities.
 *
 * Each row attaches one policy to one grantee within one scope: platform-wide
 * (null tenant columns) or one tenant, optionally that tenant's subtree, and
 * optionally one application. The same policy may be attached to the same
 * grantee once per scope.
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
        $table = config('authorization.tables.authorizable_policies', 'authorizable_policies');
        /** @var string $policiesTable */
        $policiesTable = config('authorization.tables.policies', 'policies');

        $schema = Schema::connection($this->getConnection());

        (new MigrationCollisionGuard($schema))->ensureNotExists($table);

        $schema->create($table, static function (Blueprint $blueprint) use ($table, $policiesTable): void {
            $blueprint->uuid('policy_id');

            // The grantee. References are bounded to 191 characters, as the
            // suite bounds them.
            $blueprint->string('authorizable_type', 191);
            $blueprint->string('authorizable_id', 191);

            // The scope: both tenant columns null attach platform-wide, a pair
            // attaches within that tenant, and its subtree unless
            // `include_subtree` is false. A null application attaches in every
            // application.
            $blueprint->string('tenant_type', 191)->nullable();
            $blueprint->string('tenant_id', 191)->nullable();
            $blueprint->boolean('include_subtree')->default(true);
            $blueprint->string('application', 191)->nullable();

            // Optional expiry for temporal attachments, in UTC; null means
            // "forever". The grant pivot converts every expiry to UTC before
            // writing it and reads it back as UTC, since a `dateTime` keeps no
            // zone. Rows whose `expires_at` is in the past are filtered out of
            // the relation on read. A `dateTime` rather than a `timestamp`,
            // which stops at 2038 on MySQL.
            $blueprint->dateTime('expires_at')->nullable();

            // Who attached the policy, when the caller names them.
            $blueprint->string('granted_by_type', 191)->nullable();
            $blueprint->string('granted_by_id', 191)->nullable();

            $blueprint->timestamps();

            $blueprint->index(['authorizable_type', 'authorizable_id'], $table . '_morph_index');
            $blueprint->index(['tenant_type', 'tenant_id'], $table . '_tenant_index');
            $blueprint->index('expires_at', $table . '_expires_at_index');

            $blueprint->foreign('policy_id')->references('id')->on($policiesTable)->cascadeOnDelete();
        });

        // A policy is attached to a grantee at most once per scope, with null
        // tenant columns (platform-wide) and a null application (every
        // application) each counting as one value.
        (new NullFoldingUniqueIndex($schema->getConnection()))->createDigested(
            $table,
            $table . '_unique',
            ['policy_id', 'authorizable_type', 'authorizable_id'],
            ['tenant_type', 'tenant_id', 'application'],
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
