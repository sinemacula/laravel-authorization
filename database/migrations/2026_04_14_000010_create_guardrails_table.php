<?php

/**
 * Create the `guardrails` table: the guardrails set on tenants and on the
 * platform (AUTHZ-7.6).
 *
 * Each row sets one managed policy as a guardrail within one scope:
 * platform-wide (null tenant columns) or one tenant, and that tenant's subtree
 * through the tenant tree. A policy is set at most once per scope, and a scope
 * may have any number of guardrails, every one of which must allow a check. A
 * policy in use as a guardrail is neither edited nor deleted until the
 * guardrail is removed.
 *
 * The tenant and granted-by columns compare their exact bytes on every
 * database: on MySQL they are collated `utf8mb4_0900_bin`, which neither folds
 * case nor pads trailing spaces (`ExactReferences`), so a tenant whose key
 * differs from another's only by case or a trailing space is a different one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Authorization\Config\TableNames;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Database\ExactReferences;
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
        $table         = TableNames::get('guardrails');
        $policiesTable = TableNames::get('policies');

        $schema = Schema::connection($this->getConnection());

        (new MigrationCollisionGuard($schema))->ensureNotExists($table);

        $exact = new ExactReferences($schema->getConnection());

        $schema->create($table, static function (Blueprint $blueprint) use ($table, $policiesTable, $exact): void {
            $blueprint->uuid('policy_id');

            // The scope: both tenant columns null set the guardrail
            // platform-wide, a pair sets it on that tenant and its subtree.
            // References are bounded to 191 characters, as the suite bounds
            // them.
            $blueprint->string('tenant_type', 191)->nullable();
            $blueprint->string('tenant_id', 191)->nullable();

            // Who set the guardrail, as the guardrail service records them.
            $blueprint->string('granted_by_type', 191)->nullable();
            $blueprint->string('granted_by_id', 191)->nullable();

            $blueprint->timestamps();

            $blueprint->index(['tenant_type', 'tenant_id'], $table . '_tenant_index');
            $blueprint->index('policy_id', $table . '_policy_index');

            // A policy in use as a guardrail is never deleted from under it:
            // the policy observer refuses the delete first, and the key refuses
            // one made past the model.
            $blueprint->foreign('policy_id')->references('id')->on($policiesTable)->restrictOnDelete();

            // On MySQL the reference columns compare their exact bytes, as on
            // the other databases.
            $exact->apply($blueprint);
        });

        // A policy is set as a guardrail at most once per scope, with null
        // tenant columns (platform-wide) counting as one value.
        (new NullFoldingUniqueIndex($schema->getConnection()))->createDigested(
            $table,
            $table . '_unique',
            ['policy_id'],
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
        $table = TableNames::get('guardrails');

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
