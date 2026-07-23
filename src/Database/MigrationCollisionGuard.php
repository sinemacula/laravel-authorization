<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Database;

use Illuminate\Support\Facades\Schema;

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
final class MigrationCollisionGuard
{
    /**
     * Raise a dedicated collision exception when a table of the supplied name
     * already exists.
     *
     * @param  string  $table
     * @return void
     *
     * @throws \SineMacula\Laravel\Authorization\Database\MigrationCollisionException
     */
    public static function ensureNotExists(string $table): void
    {
        if (Schema::hasTable($table)) {
            throw new MigrationCollisionException($table);
        }
    }
}
