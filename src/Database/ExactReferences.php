<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Database;

use Illuminate\Database\Connection;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Schema\ColumnDefinition;

/**
 * Makes the reference columns of a package table compare their exact bytes on
 * every database.
 *
 * A reference column holds a morph type, a key or an application: the tenant,
 * the grantee, the resource, an inline policy's owner, who made a grant, who
 * ended a break-glass activation, and the application a grant holds in. The
 * package compares references in PHP byte for byte, and PostgreSQL and SQLite
 * compare these columns the same way. MySQL compares a column through its
 * collation, and the usual defaults are case-insensitive and pad trailing
 * spaces, so a check, which matches grants, attachments and owned records in
 * SQL, would read a grant in tenant `org` in tenant `ORG`, or a policy on
 * record `abc` on record `abc `. On MySQL this class gives each reference
 * column `utf8mb4_0900_bin`, which compares bytes and does not pad, so the
 * database draws the line where the package does. The other databases are left
 * as they are, and so are every other column, names and guards included.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ExactReferences
{
    /** @var string The collation every reference column has on MySQL. */
    public const string COLLATION = 'utf8mb4_0900_bin';

    /** @var string The character set that collation belongs to. */
    public const string CHARSET = 'utf8mb4';

    /** @var list<string> The names of the package's reference columns. */
    public const array COLUMNS = [
        'tenant_type',
        'tenant_id',
        'authorizable_type',
        'authorizable_id',
        'resource_type',
        'resource_id',
        'owner_type',
        'owner_id',
        'granted_by_type',
        'granted_by_id',
        'ended_by_type',
        'ended_by_id',
        'application',
    ];

    /**
     * Create a new reference column collator.
     *
     * @param  \Illuminate\Database\Connection  $connection
     */
    public function __construct(

        /** Connection the table is created on, the one it lives on. */
        private Connection $connection,
    ) {}

    /**
     * Give each reference column the blueprint adds the byte-exact collation,
     * on MySQL only.
     *
     * Called once the table's columns are declared, before the blueprint is
     * built, so the collation is part of each column's definition.
     *
     * @param  \Illuminate\Database\Schema\Blueprint  $blueprint
     * @return void
     */
    public function apply(Blueprint $blueprint): void
    {
        if ($this->connection->getDriverName() !== 'mysql') {
            return;
        }

        $columns = \array_filter(
            $blueprint->getAddedColumns(),
            static fn (ColumnDefinition $column): bool => \in_array($column->get('name'), self::COLUMNS, true),
        );

        foreach ($columns as $column) {
            $column->charset(self::CHARSET)->collation(self::COLLATION);
        }
    }
}
