<?php

/**
 * Add the indexes the rows naming half a tenant are found through (N130).
 *
 * A row naming half a tenant, a type without a key or a key without a type,
 * which the package never writes, restricts everywhere: a guardrail stored that
 * way caps every check, and the denies of a policy attachment or of a policy
 * stored that way count in every scope (see `Support\TenantColumns`). The
 * readers that look for such rows across the whole of a table, not a grantee's
 * or a record's rows, read the two halves apart, each through an index:
 *
 * - a key without a type through each table's tenant index, which leads with
 *   the type, so the rows whose type is null are a range of it;
 * - a type without a key through `{table}_tenant_id_index`, added here on
 *   `tenant_id` and then `tenant_type` of `guardrails`, `resource_policies` and
 *   `policies`, so the rows whose key is null are a range of it, as the tenant
 *   index, leading with the type, cannot find them without reading every
 *   tenant's.
 *
 * With no such row, each read finds nothing in a range of an index, so a check
 * does no more work than it would without them. The other tables are read for
 * one grantee's or one record's rows, through their morph or resource index, so
 * a half tenant is filtered among those rows alone.
 *
 * The tables are those configured, on the package's connection. An index that
 * exists already is kept.
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

return new class extends Migration {
    /** @var list<string> The tables indexed, each by its config key, which is its default name too. */
    private const array TABLES = ['policies', 'guardrails', 'resource_policies'];

    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up(): void
    {
        $schema = Schema::connection($this->getConnection());

        foreach (self::tables() as $table) {
            $index = $table . '_tenant_id_index';

            if ($schema->hasIndex($table, $index)) {
                continue;
            }

            $schema->table($table, static function (Blueprint $blueprint) use ($index): void {
                $blueprint->index(['tenant_id', 'tenant_type'], $index);
            });
        }
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down(): void
    {
        $schema = Schema::connection($this->getConnection());

        foreach (self::tables() as $table) {
            $index = $table . '_tenant_id_index';

            if (!$schema->hasTable($table) || !$schema->hasIndex($table, $index)) {
                continue;
            }

            $schema->table($table, static function (Blueprint $blueprint) use ($index): void {
                $blueprint->dropIndex($index);
            });
        }
    }

    /**
     * The connection the tables live on, the one the package's models read and
     * write them on: `authorization.connection`, or the default when unset.
     *
     * @return string|null
     */
    #[Override]
    public function getConnection(): ?string
    {
        return AuthorizationConnection::name();
    }

    /**
     * Return the configured names of the tables indexed.
     *
     * @return list<string>
     */
    private static function tables(): array
    {
        $tables = [];

        foreach (self::TABLES as $key) {
            $tables[] = TableNames::get($key);
        }

        return $tables;
    }
};
