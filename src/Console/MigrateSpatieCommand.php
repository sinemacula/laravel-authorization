<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Console;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;

/**
 * Migrate data from Spatie's `laravel-permission` tables into this
 * package's schema.
 *
 * Reads Spatie's default table names (`roles`, `permissions`,
 * `model_has_roles`, `model_has_permissions`, `role_has_permissions`)
 * and copies rows into this package's tables, mapping column names
 * and generating UUIDs when Spatie used auto-increment IDs.
 * Everything runs inside a transaction; the `--dry-run` flag
 * reports counts without writing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
class MigrateSpatieCommand extends Command
{
    /**
     * Spatie source table names.
     *
     * @var list<string>
     */
    private const array SPATIE_TABLES = [
        'roles',
        'permissions',
        'role_has_permissions',
        'model_has_roles',
        'model_has_permissions',
    ];

    /**
     * The console command signature.
     *
     * @var string
     */
    protected $signature = <<<'EOD'
        authorization:migrate-spatie
                                    {--dry-run : Report counts without writing}
        EOD;

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Migrate data from Spatie laravel-permission tables into this package';

    /**
     * Execute the console command.
     *
     * @return int
     */
    public function handle(): int
    {
        if (!$this->verifySourceSchema()) {
            return self::FAILURE;
        }

        if (!$this->verifyTargetSchema()) {
            return self::FAILURE;
        }

        /** @var bool $dryRun */
        $dryRun = (bool) $this->option('dry-run');

        if ($dryRun) {
            $this->info('Dry run — no data will be written.');
            $this->line('');
        }

        /** @var array<string, int> $counts */
        $counts = [
            'roles'                    => 0,
            'permissions'              => 0,
            'role_permissions'         => 0,
            'authorizable_roles'       => 0,
            'authorizable_permissions' => 0,
        ];

        /** @var array<int|string, string> $roleIdMap */
        $roleIdMap = [];

        /** @var array<int|string, string> $permissionIdMap */
        $permissionIdMap = [];

        $callback = function () use ($dryRun, &$counts, &$roleIdMap, &$permissionIdMap): void {
            $roleIdMap       = $this->migrateRoles($dryRun, $counts);
            $permissionIdMap = $this->migratePermissions($dryRun, $counts);
            $this->migrateRolePermissions($roleIdMap, $permissionIdMap, $dryRun, $counts);
            $this->migrateModelHasRoles($roleIdMap, $dryRun, $counts);
            $this->migrateModelHasPermissions($permissionIdMap, $dryRun, $counts);
        };

        if ($dryRun) {
            $callback();
        } else {
            DB::transaction($callback);
        }

        $this->line('');
        $this->info('Migration summary:');
        $this->table(
            ['Target Table', 'Rows'],
            \array_map(
                static fn (string $table, int $count): array => [$table, (string) $count],
                \array_keys($counts),
                \array_values($counts),
            ),
        );

        if ($dryRun) {
            $this->line('');
            $this->warn('No data was written (dry run). Re-run without --dry-run to apply.');
        }

        return self::SUCCESS;
    }

    /**
     * Verify that all Spatie source tables exist.
     *
     * @return bool
     */
    private function verifySourceSchema(): bool
    {
        foreach (self::SPATIE_TABLES as $table) {
            if (!Schema::hasTable($table)) {
                $this->error("Spatie source table '{$table}' does not exist.");

                return false;
            }
        }

        return true;
    }

    /**
     * Verify that all target tables exist.
     *
     * @return bool
     */
    private function verifyTargetSchema(): bool
    {
        $targets = [
            'authorization.tables.roles'                    => 'roles',
            'authorization.tables.permissions'              => 'permissions',
            'authorization.tables.role_permissions'         => 'role_permissions',
            'authorization.tables.authorizable_roles'       => 'authorizable_roles',
            'authorization.tables.authorizable_permissions' => 'authorizable_permissions',
        ];

        foreach ($targets as $configKey => $default) {
            /** @var string $table */
            $table = config($configKey, $default);

            if (!Schema::hasTable($table)) {
                $this->error("Target table '{$table}' does not exist. Run the package migrations first.");

                return false;
            }
        }

        return true;
    }

    /**
     * Migrate roles from Spatie's `roles` table.
     *
     * @param  bool  $dryRun
     * @param  array<string, int>  $counts
     * @return array<int|string, string>
     */
    private function migrateRoles(bool $dryRun, array &$counts): array
    {
        /** @var string $targetTable */
        $targetTable = config('authorization.tables.roles', 'roles');

        /** @var array<int|string, string> $idMap */
        $idMap = [];

        $rows = DB::table('roles')->get();

        foreach ($rows as $row) {
            /** @var array{id: int|string, name: string, guard_name: string|null, created_at: string|null, updated_at: string|null} $data */
            $data  = (array) $row;
            $newId = \is_int($data['id']) ? (string) Str::orderedUuid() : $data['id'];

            $idMap[$data['id']] = $newId;

            if (!$dryRun) {
                DB::table($targetTable)->insert([
                    'id'         => $newId,
                    'name'       => $data['name'],
                    'guard_name' => $data['guard_name'] ?? null,
                    'created_at' => $data['created_at'] ?? now(),
                    'updated_at' => $data['updated_at'] ?? now(),
                ]);
            }

            $counts['roles']++;
        }

        return $idMap;
    }

    /**
     * Migrate permissions from Spatie's `permissions` table.
     *
     * @param  bool  $dryRun
     * @param  array<string, int>  $counts
     * @return array<int|string, string>
     */
    private function migratePermissions(bool $dryRun, array &$counts): array
    {
        /** @var string $targetTable */
        $targetTable = config('authorization.tables.permissions', 'permissions');

        /** @var array<int|string, string> $idMap */
        $idMap = [];

        $rows = DB::table('permissions')->get();

        foreach ($rows as $row) {
            /** @var array{id: int|string, name: string, guard_name: string|null, created_at: string|null, updated_at: string|null} $data */
            $data  = (array) $row;
            $newId = \is_int($data['id']) ? (string) Str::orderedUuid() : $data['id'];

            $idMap[$data['id']] = $newId;

            if (!$dryRun) {
                DB::table($targetTable)->insert([
                    'id'         => $newId,
                    'name'       => $data['name'],
                    'guard_name' => $data['guard_name'] ?? null,
                    'created_at' => $data['created_at'] ?? now(),
                    'updated_at' => $data['updated_at'] ?? now(),
                ]);
            }

            $counts['permissions']++;
        }

        return $idMap;
    }

    /**
     * Migrate `role_has_permissions` to `role_permissions`.
     *
     * @param  array<int|string, string>  $roleIdMap
     * @param  array<int|string, string>  $permissionIdMap
     * @param  bool  $dryRun
     * @param  array<string, int>  $counts
     * @return void
     */
    private function migrateRolePermissions(array $roleIdMap, array $permissionIdMap, bool $dryRun, array &$counts): void
    {
        /** @var string $targetTable */
        $targetTable = config('authorization.tables.role_permissions', 'role_permissions');

        $rows = DB::table('role_has_permissions')->get();

        foreach ($rows as $row) {
            /** @var array{permission_id: int|string, role_id: int|string} $data */
            $data               = (array) $row;
            $mappedRoleId       = $roleIdMap[$data['role_id']]             ?? null;
            $mappedPermissionId = $permissionIdMap[$data['permission_id']] ?? null;

            if ($mappedRoleId === null || $mappedPermissionId === null) {
                continue;
            }

            if (!$dryRun) {
                DB::table($targetTable)->insert([
                    'role_id'       => $mappedRoleId,
                    'permission_id' => $mappedPermissionId,
                ]);
            }

            $counts['role_permissions']++;
        }
    }

    /**
     * Migrate `model_has_roles` to `authorizable_roles`.
     *
     * @param  array<int|string, string>  $roleIdMap
     * @param  bool  $dryRun
     * @param  array<string, int>  $counts
     * @return void
     */
    private function migrateModelHasRoles(array $roleIdMap, bool $dryRun, array &$counts): void
    {
        /** @var string $targetTable */
        $targetTable = config('authorization.tables.authorizable_roles', 'authorizable_roles');

        $rows = DB::table('model_has_roles')->get();

        foreach ($rows as $row) {
            /** @var array{role_id: int|string, model_type: string, model_id: int|string} $data */
            $data         = (array) $row;
            $mappedRoleId = $roleIdMap[$data['role_id']] ?? null;

            if ($mappedRoleId === null) {
                continue;
            }

            if (!$dryRun) {
                DB::table($targetTable)->insert([
                    'authorizable_type' => $data['model_type'],
                    'authorizable_id'   => (string) $data['model_id'],
                    'role_id'           => $mappedRoleId,
                ]);
            }

            $counts['authorizable_roles']++;
        }
    }

    /**
     * Migrate `model_has_permissions` to `authorizable_permissions`.
     *
     * @param  array<int|string, string>  $permissionIdMap
     * @param  bool  $dryRun
     * @param  array<string, int>  $counts
     * @return void
     */
    private function migrateModelHasPermissions(array $permissionIdMap, bool $dryRun, array &$counts): void
    {
        /** @var string $targetTable */
        $targetTable = config('authorization.tables.authorizable_permissions', 'authorizable_permissions');

        $rows = DB::table('model_has_permissions')->get();

        foreach ($rows as $row) {
            /** @var array{permission_id: int|string, model_type: string, model_id: int|string} $data */
            $data               = (array) $row;
            $mappedPermissionId = $permissionIdMap[$data['permission_id']] ?? null;

            if ($mappedPermissionId === null) {
                continue;
            }

            if (!$dryRun) {
                DB::table($targetTable)->insert([
                    'authorizable_type' => $data['model_type'],
                    'authorizable_id'   => (string) $data['model_id'],
                    'permission_id'     => $mappedPermissionId,
                ]);
            }

            $counts['authorizable_permissions']++;
        }
    }
}
