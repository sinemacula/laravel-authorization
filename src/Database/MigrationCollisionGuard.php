<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Database;

use Illuminate\Database\Schema\Builder;

/**
 * Idempotency guard for shipped migrations.
 *
 * Each published migration invokes the guard on `up()` so subsequent matrix
 * runs against a persistent database do not silently collide with an unrelated
 * table of the same name.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class MigrationCollisionGuard
{
    /**
     * Create a new collision guard instance.
     *
     * @param  \Illuminate\Database\Schema\Builder  $schema
     */
    public function __construct(

        /** Schema builder used to probe the database for an existing table. */
        private Builder $schema,

    ) {}

    /**
     * Raise a dedicated collision exception when a table of the supplied name
     * already exists.
     *
     * @param  string  $table
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Database\MigrationCollisionException
     */
    public function ensureNotExists(string $table): void
    {
        if ($this->schema->hasTable($table)) {
            throw new MigrationCollisionException($table);
        }
    }
}
