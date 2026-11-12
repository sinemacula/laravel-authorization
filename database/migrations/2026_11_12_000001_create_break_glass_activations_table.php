<?php

/**
 * Create the break-glass activations table (AUTHZ-11.7, N133): each row one
 * activation of an emergency role for one principal, for a limited time.
 *
 * Every activation is its own record with its own expiry, beside any normal
 * grant of the same role, so it is never deduplicated: the table has no unique
 * index but its key. A live activation, one not ended whose expiry is still to
 * come, grants its role in its scope as a role grant would (see
 * `Database\BreakGlassActivations`). The scope is the platform (both tenant
 * columns null) or one tenant, and its subtree unless `include_subtree` is
 * false, optionally in one application. The note, when the application allows
 * one, is personal data: it is never cached, logged or put on an event.
 *
 * The indexes serve the resolution (a grantee's activations by expiry, and the
 * tenant) and the reviews (a role's activations by expiry). The table honours
 * the configured name, the prefix and the package's connection, and its
 * reference columns compare their exact bytes on every database, as the grant
 * tables' do (`ExactReferences`).
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
        $table      = TableNames::get('break_glass');
        $rolesTable = TableNames::get('roles');

        $schema = Schema::connection($this->getConnection());

        (new MigrationCollisionGuard($schema))->ensureNotExists($table);

        $exact = new ExactReferences($schema->getConnection());

        $schema->create($table, static function (Blueprint $blueprint) use ($table, $rolesTable, $exact): void {
            $blueprint->uuid('id')->primary();
            $blueprint->uuid('role_id');

            // The grantee, a human principal, and who activated it for them,
            // null for none. References are bounded to 191 characters, as the
            // suite bounds them.
            $blueprint->string('authorizable_type', 191);
            $blueprint->string('authorizable_id', 191);
            $blueprint->string('granted_by_type', 191)->nullable();
            $blueprint->string('granted_by_id', 191)->nullable();

            // The scope, as a role grant's: both tenant columns null for the
            // platform, else one tenant, and its subtree unless
            // `include_subtree` is false; a null application holds in every
            // application.
            $blueprint->string('tenant_type', 191)->nullable();
            $blueprint->string('tenant_id', 191)->nullable();
            $blueprint->boolean('include_subtree')->default(true);
            $blueprint->string('application', 191)->nullable();

            // Why: a justification code from the configured list, and a
            // free-text note, personal data, when the application allows one.
            $blueprint->string('justification', 64);
            $blueprint->text('note')->nullable();

            // When, in UTC: an activation always expires.
            $blueprint->dateTime('activated_at');
            $blueprint->dateTime('expires_at');

            // How it ended before its expiry, if it did: when, by whom, and
            // `surrendered`, `revoked` or `expired`.
            $blueprint->dateTime('ended_at')->nullable();
            $blueprint->string('ended_by_type', 191)->nullable();
            $blueprint->string('ended_by_id', 191)->nullable();
            $blueprint->string('end_reason', 16)->nullable();

            $blueprint->index(['authorizable_type', 'authorizable_id', 'expires_at'], $table . '_grantee_index');
            $blueprint->index(['tenant_type', 'tenant_id'], $table . '_tenant_index');
            $blueprint->index(['role_id', 'expires_at'], $table . '_role_index');

            $blueprint->foreign('role_id')->references('id')->on($rolesTable)->cascadeOnDelete();

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
        $table = TableNames::get('break_glass');

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
