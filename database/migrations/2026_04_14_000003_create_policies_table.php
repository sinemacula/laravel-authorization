<?php

/**
 * Create the `policies` table.
 *
 * Policies are JSON documents of allow and deny statements attached to
 * authorizable identities and roles. A policy is owned by the platform (null
 * tenant columns) or by one tenant, and its name is unique within its owner. An
 * inline policy also names the one grantee it belongs to, and its name is
 * unique among that grantee's inline policies.
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
        $table  = config('authorization.tables.policies', 'policies');
        $schema = Schema::connection($this->getConnection());

        (new MigrationCollisionGuard($schema))->ensureNotExists($table);

        $schema->create($table, static function (Blueprint $blueprint) use ($table): void {
            $blueprint->uuid('id')->primary();

            // Names, tenant types and tenant ids are bounded to 191 characters,
            // so the unique key below stays within MySQL's 3072-byte InnoDB key
            // limit under `utf8mb4`.
            $blueprint->string('name', 191);
            $blueprint->string('description')->nullable();

            // Platform-protection marker. Policies flagged system refuse delete
            // and every edit, clearing this flag included, unless the
            // model-layer `forceSystem()` escape hatch is invoked, so a
            // platform-shipped `break-glass` policy cannot be casually removed
            // or changed by a caller with raw Eloquent access.
            $blueprint->boolean('is_system')->default(false);

            $blueprint->json('document');

            // The tenant that owns the policy. Both columns null mark the
            // policy as platform-wide; a concrete pair marks it as owned by
            // that tenant.
            $blueprint->string('tenant_type', 191)->nullable();
            $blueprint->string('tenant_id', 191)->nullable();

            // The grantee an inline policy belongs to, apart from the tenant
            // that owns it. Both columns null mark a managed policy, attachable
            // to any grantee; a concrete pair marks an inline one, attachable
            // only to that grantee and deleted with it. Grantees are morphs, so
            // there is no foreign key: `authorization:prune` removes the inline
            // policies of a grantee that no longer exists.
            $blueprint->string('owner_type', 191)->nullable();
            $blueprint->string('owner_id', 191)->nullable();

            $blueprint->timestamps();

            $blueprint->index('name', $table . '_name_index');
            $blueprint->index(['tenant_type', 'tenant_id'], $table . '_tenant_index');
            $blueprint->index(['owner_type', 'owner_id'], $table . '_owner_index');

            // An inline policy's name is unique among its grantee's inline
            // policies. A managed policy's null owner columns are distinct from
            // each other inside the index, so this key never compares two
            // managed policies.
            $blueprint->unique(['name', 'owner_type', 'owner_id'], $table . '_name_inline_unique');
        });

        // A managed policy's name is unique within its tenant: at most one row
        // per name and tenant, with null tenant columns (platform-wide)
        // counting as one value. A platform policy and a tenant's policy may
        // share a name, and two tenants may each have their own. The owner
        // columns, folded the same way, keep inline policies out of the
        // comparison, so a grantee's inline policy may share a managed policy's
        // name. The key is digested on MySQL, where the name and four folded
        // columns would not fit.
        (new NullFoldingUniqueIndex($schema->getConnection()))->createDigested(
            $table,
            $table . '_name_owner_unique',
            ['name'],
            ['tenant_type', 'tenant_id', 'owner_type', 'owner_id'],
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
        $table = config('authorization.tables.policies', 'policies');

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
