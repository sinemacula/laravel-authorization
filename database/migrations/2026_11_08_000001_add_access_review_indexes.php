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
 * - `{table}_review_order_index`, on PostgreSQL only, on each grant table's
 *   target and its grantee's type and key, each collated `C`: the order a page
 *   of a target's direct holders is read in (see
 *   `Reviews\Support\ReviewOrder`), so a page seeks to its keyset through the
 *   index, and the planner can walk it in order, reading about the rows the
 *   page returns and sorting only the grants each grantee holds of the target.
 *
 * The other review queries are already served: a grantee's grants by its morph
 * index, an expiry window by each table's `expires_at` index, and, on MySQL and
 * SQLite, a target's grants by each grant table's unique index, which leads
 * with the target and the grantee and, on those databases, compares their
 * bytes. On MySQL that index holds digests of the tenant and the application,
 * not their values, so a page of a target's holders seeks to its keyset and
 * reads the target's grants from there on, then sorts them for the page: its
 * work grows with the target's grants after the page, never with the tenant's.
 * A review of an expiry window or of an actor's grants, and the routes through
 * the roles below a target, read every row their filter matches from the page's
 * keyset on and sort them, so a page's work grows with the rows that window,
 * actor or those roles match; only the sort's top rows are bounded by the page.
 * No page is read at an offset.
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
use SineMacula\Laravel\Authorization\Config\TableNames;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;

return new class extends Migration {
    /** @var array<string, string> The grant tables, each by its config key, with its target column. */
    private const array GRANTS = [
        'authorizable_roles'       => 'role_id',
        'authorizable_permissions' => 'permission_id',
        'authorizable_policies'    => 'policy_id',
    ];

    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up(): void
    {
        $schema = Schema::connection($this->getConnection());

        foreach (self::grantTables() as $table => $target) {
            self::addOrderIndex($schema, $table, $target);

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

        foreach (array_keys(self::grantTables()) as $table) {
            self::dropIndex($schema, $table, $table . '_granted_by_index');
            self::dropIndex($schema, $table, $table . '_review_order_index');
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
     * Add, on PostgreSQL, the index a page of a target's direct holders is read
     * through, unless it exists: the target, then the grantee's type and key
     * collated `C`, as the page orders and resumes by them.
     *
     * @param  \Illuminate\Database\Schema\Builder  $schema
     * @param  string  $table
     * @param  string  $target
     * @return void
     */
    private static function addOrderIndex(Builder $schema, string $table, string $target): void
    {
        $connection = $schema->getConnection();
        $index      = $table . '_review_order_index';

        if ($connection->getDriverName() !== 'pgsql' || $schema->hasIndex($table, $index)) {
            return;
        }

        $grammar = $connection->getQueryGrammar();

        $connection->statement(sprintf(
            'CREATE INDEX %s ON %s (%s, (%s COLLATE "C"), (%s COLLATE "C"))',
            $grammar->wrap($index),
            $grammar->wrapTable($table),
            $grammar->wrap($target),
            $grammar->wrap('authorizable_type'),
            $grammar->wrap('authorizable_id'),
        ));
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
     * Return the configured names of the grant tables, each with its target
     * column.
     *
     * @return array<string, string>
     */
    private static function grantTables(): array
    {
        $tables = [];

        foreach (self::GRANTS as $key => $target) {
            $tables[TableNames::get($key)] = $target;
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
        return TableNames::get('role_permissions');
    }
};
