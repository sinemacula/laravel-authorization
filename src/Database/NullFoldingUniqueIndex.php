<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Database;

use Illuminate\Database\Connection;

/**
 * Creates a unique index in which a null counts as a value.
 *
 * MySQL, PostgreSQL and SQLite all treat nulls as distinct inside a unique
 * index, so an ordinary unique key over a nullable column admits any number of
 * rows that differ only by a null: two platform-wide roles of one name, or two
 * guard-agnostic ones. The index this class creates compares each nullable
 * column through `COALESCE(column, '')`, an expression all three databases
 * accept in an index, so a null takes part in the key as an empty string and at
 * most one row holds each combination.
 *
 * A digested index compares each nullable column by the SHA-256 digest of its
 * folded value on MySQL instead, where InnoDB caps a key at 3072 bytes and
 * reserves four bytes for each character of a `utf8mb4` column: a grant's key,
 * with the grantee, the tenant and the application in it, would not fit
 * otherwise. The digest is of the folded value's bytes, so it keeps apart the
 * same values as the byte-exact collation MySQL gives the reference columns
 * (`ExactReferences`), through which an index that is not digested compares
 * them. The other databases have no such cap and compare the folded value
 * itself.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class NullFoldingUniqueIndex
{
    /**
     * Create a new index builder.
     *
     * @param  \Illuminate\Database\Connection  $connection
     */
    public function __construct(

        /** Connection the index is created on, the one its table lives on. */
        private Connection $connection,
    ) {}

    /**
     * Create the index over the given columns, comparing each nullable column
     * with its null folded to an empty string.
     *
     * @param  string  $table
     * @param  string  $name
     * @param  list<string>  $columns
     * @param  list<string>  $nullable
     * @return void
     */
    public function create(string $table, string $name, array $columns, array $nullable): void
    {
        $this->build($table, $name, $columns, $nullable, false);
    }

    /**
     * Create the index over the given columns, comparing each nullable column
     * with its null folded to an empty string, by the digest of the folded
     * value on MySQL.
     *
     * @param  string  $table
     * @param  string  $name
     * @param  list<string>  $columns
     * @param  list<string>  $nullable
     * @return void
     */
    public function createDigested(string $table, string $name, array $columns, array $nullable): void
    {
        $this->build($table, $name, $columns, $nullable, $this->connection->getDriverName() === 'mysql');
    }

    /**
     * Build and run the `CREATE UNIQUE INDEX` statement.
     *
     * @param  string  $table
     * @param  string  $name
     * @param  list<string>  $columns
     * @param  list<string>  $nullable
     * @param  bool  $digest
     * @return void
     */
    private function build(string $table, string $name, array $columns, array $nullable, bool $digest): void
    {
        $grammar = $this->connection->getQueryGrammar();
        $parts   = \array_map($grammar->wrap(...), $columns);

        foreach ($nullable as $column) {
            $folded  = 'COALESCE(' . $grammar->wrap($column) . ', \'\')';
            $parts[] = '(' . ($digest ? 'SHA2(' . $folded . ', 256)' : $folded) . ')';
        }

        $this->connection->statement(\sprintf(
            'CREATE UNIQUE INDEX %s ON %s (%s)',
            $grammar->wrap($name),
            $grammar->wrapTable($table),
            \implode(', ', $parts),
        ));
    }
}
