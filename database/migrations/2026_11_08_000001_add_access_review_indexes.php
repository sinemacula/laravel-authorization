<?php

/**
 * Add the indexes access reviews read through (AUTHZ-11.6, N95, N98).
 *
 * - `{table}_granted_by_index` on `granted_by_type` and `granted_by_id` of each
 *   grant table (`authorizable_roles`, `authorizable_permissions` and
 *   `authorizable_policies`), which a review of an actor's grants matches
 *   exactly.
 * - `{table}_permission_id_index` on the `permission_id` of `role_permissions`,
 *   which a review of a permission's holders reads the roles carrying it by,
 *   since the table's primary key leads with the role. A database that already
 *   indexes the column for its foreign key, as MySQL does, keeps that index,
 *   and this one is not added.
 *
 * The other review queries are already served: a target's grants by each grant
 * table's unique index, which leads with the target, a grantee's by its morph
 * index, and an expiry window by each table's `expires_at` index. A review
 * orders its rows byte for byte (see `Reviews\Support\ReviewOrder`), which no
 * index on a collated column orders by, so the database sorts the rows each
 * page selects; a page is bounded by its limit, and resumes from its keyset,
 * never an offset.
 *
 * The tables are those configured, on the package's connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

declare(strict_types = 1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Schema\Builder;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;

return new class extends Migration {
    /** @var list<array{string, string}> The grant tables, each by its config key and default name. */
    private const array GRANTS = [
        ['authorizable_roles', 'authorizable_roles'],
        ['authorizable_permissions', 'authorizable_permissions'],
        ['authorizable_policies', 'authorizable_policies'],
    ];

    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up(): void
    {
        $schema = Schema::connection($this->getConnection());

        foreach (self::grantTables() as $table) {
            if ($schema->hasIndex($table, $table . '_granted_by_index')) {
                continue;
            }

            $schema->table($table, static function (Blueprint $blueprint) use ($table): void {
                $blueprint->index(['granted_by_type', 'granted_by_id'], $table . '_granted_by_index');
            });
        }

        $edges = self::edgesTable();

        if ($schema->hasIndex($edges, ['permission_id'])) {
            return;
        }

        $schema->table($edges, static function (Blueprint $blueprint) use ($edges): void {
            $blueprint->index('permission_id', $edges . '_permission_id_index');
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down(): void
    {
        $schema = Schema::connection($this->getConnection());

        foreach (self::grantTables() as $table) {
            self::dropIndex($schema, $table, $table . '_granted_by_index');
        }

        $edges = self::edgesTable();

        self::dropIndex($schema, $edges, $edges . '_permission_id_index');
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
     * Drop the index of the table when it exists.
     *
     * @param  \Illuminate\Database\Schema\Builder  $schema
     * @param  string  $table
     * @param  string  $index
     * @return void
     */
    private static function dropIndex(Builder $schema, string $table, string $index): void
    {
        if (!$schema->hasTable($table) || !$schema->hasIndex($table, $index)) {
            return;
        }

        $schema->table($table, static function (Blueprint $blueprint) use ($index): void {
            $blueprint->dropIndex($index);
        });
    }

    /**
     * Return the configured names of the grant tables.
     *
     * @return list<string>
     */
    private static function grantTables(): array
    {
        $tables = [];

        foreach (self::GRANTS as [$key, $default]) {
            /** @var string $table */
            $table = config('authorization.tables.' . $key, $default);

            $tables[] = $table;
        }

        return $tables;
    }

    /**
     * Return the configured name of the role permission edges table.
     *
     * @return string
     */
    private static function edgesTable(): string
    {
        /** @var string */
        return config('authorization.tables.role_permissions', 'role_permissions');
    }
};
