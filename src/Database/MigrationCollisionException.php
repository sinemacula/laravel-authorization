<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Database;

/**
 * Thrown when a shipped migration detects that one of the
 * authorization tables already exists on the target database.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
class MigrationCollisionException extends \RuntimeException
{
    /**
     * Create a new exception instance.
     *
     * @param  string  $table
     */
    public function __construct(

        /** Table name that already existed when the migration tried to create it. */
        private readonly string $table,

    ) {
        parent::__construct(
            "Table '{$table}' already exists — authorization migrations refuse to overwrite it."
                . ' Drop the table or rename it via the authorization.tables config before re-running migrate.',
        );
    }

    /**
     * Return the table name that triggered the collision.
     *
     * @return string
     */
    public function getTable(): string
    {
        return $this->table;
    }
}
