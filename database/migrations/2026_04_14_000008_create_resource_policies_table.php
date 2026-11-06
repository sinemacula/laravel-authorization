<?php

/**
 * Create the `resource_policies` table: policies attached to resources.
 *
 * Each row attaches one managed policy to one resource, a record of a type or
 * the whole type (a null `resource_id`), within one scope: platform-wide (null
 * tenant columns) or one tenant, optionally that tenant's subtree, and
 * optionally one application. The same policy may be attached to the same
 * resource once per scope (AUTHZ-7.3).
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
        $table = config('authorization.tables.resource_policies', 'resource_policies');
        /** @var string $policiesTable */
        $policiesTable = config('authorization.tables.policies', 'policies');

        $schema = Schema::connection($this->getConnection());

        (new MigrationCollisionGuard($schema))->ensureNotExists($table);

        $schema->create($table, static function (Blueprint $blueprint) use ($table, $policiesTable): void {
            $blueprint->uuid('policy_id');

            // The resource: its morph type, and its key, or null for every
            // record of the type and a check on the type alone. References are
            // bounded to 191 characters, as the suite bounds them.
            $blueprint->string('resource_type', 191);
            $blueprint->string('resource_id', 191)->nullable();

            // The scope: both tenant columns null attach platform-wide, a pair
            // attaches within that tenant, and its subtree unless
            // `include_subtree` is false. A null application attaches in every
            // application.
            $blueprint->string('tenant_type', 191)->nullable();
            $blueprint->string('tenant_id', 191)->nullable();
            $blueprint->boolean('include_subtree')->default(true);
            $blueprint->string('application', 191)->nullable();

            $blueprint->timestamps();

            $blueprint->index(['resource_type', 'resource_id'], $table . '_resource_index');
            $blueprint->index(['tenant_type', 'tenant_id'], $table . '_tenant_index');

            $blueprint->foreign('policy_id')->references('id')->on($policiesTable)->cascadeOnDelete();
        });

        // A policy is attached to a resource at most once per scope, with a
        // null resource id (the whole type), null tenant columns
        // (platform-wide) and a null application (every application) each
        // counting as one value.
        (new NullFoldingUniqueIndex($schema->getConnection()))->createDigested(
            $table,
            $table . '_unique',
            ['policy_id', 'resource_type'],
            ['resource_id', 'tenant_type', 'tenant_id', 'application'],
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
        $table = config('authorization.tables.resource_policies', 'resource_policies');

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
