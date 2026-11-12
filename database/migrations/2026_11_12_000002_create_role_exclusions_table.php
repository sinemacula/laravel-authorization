<?php

/**
 * Create the `role_exclusions` table: the pairs of roles declared mutually
 * exclusive (AUTHZ-11.8, N135).
 *
 * Each row names two roles by key, so a pair holds whatever the roles are
 * called and whichever tenant owns them, in a canonical order, the lower key
 * first, so the pair (A, B) and the pair (B, A) are one row, which the primary
 * key keeps unique. It names the tenant that owns the pair (both tenant columns
 * null for the platform), who declared it and when. A role deleted takes its
 * pairs with it.
 *
 * Every index and key is named after the table with a short suffix of its own,
 * the longest `_excluded_foreign`, so the table's name is bounded as
 * `TableConfigValidator::LENGTHS` says. The tenant and granted-by columns
 * compare their exact bytes on every database: on MySQL they are collated
 * `utf8mb4_0900_bin` (`ExactReferences`).
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

return new class extends Migration {
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up(): void
    {
        $table      = TableNames::get('role_exclusions');
        $rolesTable = TableNames::get('roles');

        $schema = Schema::connection($this->getConnection());

        (new MigrationCollisionGuard($schema))->ensureNotExists($table);

        $exact = new ExactReferences($schema->getConnection());

        $schema->create($table, static function (Blueprint $blueprint) use ($table, $rolesTable, $exact): void {
            // The pair, the lower key first, as the role exclusion service
            // writes it.
            $blueprint->uuid('role_id');
            $blueprint->uuid('excluded_role_id');

            // The owner: both tenant columns null for the platform, a pair for
            // the tenant whose definitions may name both roles. References are
            // bounded to 191 characters, as the suite bounds them.
            $blueprint->string('tenant_type', 191)->nullable();
            $blueprint->string('tenant_id', 191)->nullable();

            // Who declared the pair, as the role exclusion service records
            // them.
            $blueprint->string('granted_by_type', 191)->nullable();
            $blueprint->string('granted_by_id', 191)->nullable();

            $blueprint->timestamps();

            $blueprint->primary(['role_id', 'excluded_role_id'], $table . '_primary');
            $blueprint->index('excluded_role_id', $table . '_excluded_index');
            $blueprint->index(['tenant_type', 'tenant_id'], $table . '_tenant_index');

            $blueprint->foreign('role_id', $table . '_role_foreign')->references('id')->on($rolesTable)->cascadeOnDelete();
            $blueprint->foreign('excluded_role_id', $table . '_excluded_foreign')->references('id')->on($rolesTable)->cascadeOnDelete();

            // On MySQL the reference columns compare their exact bytes, as on
            // the other databases.
            $exact->apply($blueprint);
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down(): void
    {
        $table = TableNames::get('role_exclusions');

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
