<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Console;

use Illuminate\Console\Command;
use Illuminate\Database\Connection;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationNameException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Services\PermissionService;
use SineMacula\Laravel\Authorization\Services\RoleService;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Migrate data from Spatie's `laravel-permission` tables into this package's
 * schema.
 *
 * Reads Spatie's default table names (`roles`, `permissions`,
 * `model_has_roles`, `model_has_permissions`, `role_has_permissions`) and
 * writes each row through the management services, so every role, permission
 * and grant is validated and reported as any other write here is, mapping
 * column names (Spatie's `guard_name` becomes `guard`) and generating UUIDs
 * when Spatie used auto-increment IDs. Role and permission names are checked
 * against the models' name rule before they are written; a name that fails it
 * is reported and skipped together with its grants, as is a permission name
 * containing `*`, because `*` is a wildcard here. Spatie's tables are read on
 * the application's default connection and this package's are written on its
 * own (`authorization.connection`); the `--dry-run` flag reports counts without
 * writing.
 *
 * The import runs in two steps. The roles, the permissions and the roles'
 * permissions are written first, in one transaction, which commits before any
 * grant is made: a failure there writes nothing. Then each Spatie grant is made
 * as a call of its own, in its own transaction, so the grant hooks of each
 * (AUTHZ-11.3) run before any lock the package takes for it, never under the
 * locks of the rows already imported. The grants are therefore not one atomic
 * write: a grant that fails, or that a hook refuses, stops the import, and the
 * roles, permissions and grants written before it stay. Run the command outside
 * any transaction of your own, so each grant's own transaction is the outermost
 * one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class MigrateSpatieCommand extends Command
{
    /** @var string The console command's name. */
    public const string NAME = 'authorization:migrate-spatie';

    /** @var list<string> Spatie source table names. */
    private const array SPATIE_TABLES = [
        'roles',
        'permissions',
        'role_has_permissions',
        'model_has_roles',
        'model_has_permissions',
    ];

    /** @var string The console command signature. */
    protected $signature = self::NAME . <<<'EOD'

                                    {--dry-run : Report counts without writing}
        EOD;

    /** @var string The console command description. */
    protected $description = 'Migrate data from Spatie laravel-permission tables into this package';

    /**
     * Create a new command instance.
     *
     * @param  \SineMacula\Laravel\Authorization\Services\RoleService  $roles
     * @param  \SineMacula\Laravel\Authorization\Services\PermissionService  $permissions
     * @param  \SineMacula\Laravel\Authorization\Services\GrantService  $grants
     */
    public function __construct(

        /** Creates the roles and grants their permissions. */
        private readonly RoleService $roles,

        /** Creates the permissions. */
        private readonly PermissionService $permissions,

        /** Grants the roles and permissions to their grantees. */
        private readonly GrantService $grants,
    ) {
        parent::__construct();
    }

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

        $catalogue = function () use ($dryRun, &$counts): array {
            $roleIdMap       = $this->migrateRoles($dryRun, $counts);
            $permissionIdMap = $this->migratePermissions($dryRun, $counts);
            $this->migrateRolePermissions($roleIdMap, $permissionIdMap, $dryRun, $counts);

            return [$roleIdMap, $permissionIdMap];
        };

        [$roleIdMap, $permissionIdMap] = $dryRun ? $catalogue() : $this->target()->transaction($catalogue);

        // Each grant is a call of its own, made once the catalogue has
        // committed, so its grant hooks run before any lock the package takes
        // for it (AUTHZ-11.3).
        $counts['authorizable_roles']       = $this->migrateGrants('model_has_roles', 'role_id', $roleIdMap, $dryRun, $this->grants->grantRole(...));
        $counts['authorizable_permissions'] = $this->migrateGrants('model_has_permissions', 'permission_id', $permissionIdMap, $dryRun, $this->grants->grantPermission(...));

        $this->renderMigrationSummary($counts, $dryRun);

        return self::SUCCESS;
    }

    /**
     * Render the post-migration summary table and the dry-run reminder when
     * applicable.
     *
     * @param  array<string, int>  $counts
     * @param  bool  $dryRun
     * @return void
     */
    private function renderMigrationSummary(array $counts, bool $dryRun): void
    {
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

        if (!$dryRun) {
            return;
        }

        $this->line('');
        $this->warn('No data was written (dry run). Re-run without --dry-run to apply.');
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
     * Verify that all target tables exist on the package's connection.
     *
     * @return bool
     */
    private function verifyTargetSchema(): bool
    {
        $schema = $this->target()->getSchemaBuilder();

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

            if (!$schema->hasTable($table)) {
                $this->error("Target table '{$table}' does not exist. Run the package migrations first.");

                return false;
            }
        }

        return true;
    }

    /**
     * Return the connection the package's tables live on, which the import
     * writes to and runs its transaction on. Spatie's tables are read on the
     * application's default connection.
     *
     * @return \Illuminate\Database\Connection
     */
    private function target(): Connection
    {
        /** @var \Illuminate\Database\Connection */
        return DB::connection(AuthorizationConnection::name());
    }

    /**
     * Migrate roles from Spatie's `roles` table through the role service, so
     * each is validated and reported as any role created here is. A Spatie
     * string id is kept; an auto-increment one is replaced by a UUID. A dry run
     * builds each role without saving it.
     *
     * @param  bool  $dryRun
     * @param  array<string, int>  $counts
     * @return array<int|string, \SineMacula\Laravel\Authorization\Models\Role>
     *
     * @throws \Throwable
     */
    private function migrateRoles(bool $dryRun, array &$counts): array
    {
        $idMap = [];

        foreach (DB::table('roles')->get() as $row) {
            /** @var array{id: int|string, name: string, guard_name?: string|null} $roleRow */
            $roleRow = (array) $row;

            if (!Role::isValidAuthorizationName($roleRow['name'])) {
                $this->reportRefusedName('role', $roleRow['name']);

                continue;
            }

            $guard = $roleRow['guard_name'] ?? null;

            $idMap[$roleRow['id']] = $dryRun
                ? new Role(['name' => $roleRow['name'], 'guard' => $guard])
                : $this->roles->create($roleRow['name'], $guard, id: self::keptId($roleRow['id']));

            $counts['roles']++;
        }

        return $idMap;
    }

    /**
     * Migrate permissions from Spatie's `permissions` table through the
     * permission service, keeping string ids as `migrateRoles()` does. A dry
     * run builds each permission without saving it.
     *
     * @param  bool  $dryRun
     * @param  array<string, int>  $counts
     * @return array<int|string, \SineMacula\Laravel\Authorization\Models\Permission>
     *
     * @throws \Throwable
     */
    private function migratePermissions(bool $dryRun, array &$counts): array
    {
        $idMap = [];

        foreach (DB::table('permissions')->get() as $row) {
            /** @var array{id: int|string, name: string, guard_name?: string|null} $permissionRow */
            $permissionRow = (array) $row;

            if (!$this->isImportablePermissionName($permissionRow['name'])) {
                continue;
            }

            $guard = $permissionRow['guard_name'] ?? null;

            $idMap[$permissionRow['id']] = $dryRun
                ? new Permission(['name' => $permissionRow['name'], 'guard' => $guard])
                : $this->permissions->create($permissionRow['name'], $guard, id: self::keptId($permissionRow['id']));

            $counts['permissions']++;
        }

        return $idMap;
    }

    /**
     * Return the id an imported row keeps: a Spatie string id as it is, else
     * null, so the model is given a new UUID.
     *
     * @param  int|string  $id
     * @return string|null
     */
    private static function keptId(int|string $id): ?string
    {
        return \is_string($id) ? $id : null;
    }

    /**
     * Determine whether a Spatie permission name can be imported.
     *
     * A name the package refuses is reported and skipped. A name containing `*`
     * is reported and skipped as well: Spatie compares it literally unless its
     * wildcard permissions are enabled, while here it would become a wildcard
     * granting every permission its pattern matches.
     *
     * @param  string  $name
     * @return bool
     */
    private function isImportablePermissionName(string $name): bool
    {
        if (!Permission::isValidAuthorizationName($name)) {
            $this->reportRefusedName('permission', $name);

            return false;
        }

        if (!\str_contains($name, '*')) {
            return true;
        }

        $this->warn(
            "Skipped: permission name '{$name}' contains '*', which is a wildcard here and would grant other "
            . 'permissions. Its grants are not migrated.',
        );

        return false;
    }

    /**
     * Report a Spatie role or permission whose name the package refuses, so it
     * and every grant that references it are skipped visibly.
     *
     * @param  string  $kind
     * @param  string  $name
     * @return void
     */
    private function reportRefusedName(string $kind, string $name): void
    {
        $reason = (new InvalidAuthorizationNameException($kind, $name))->getMessage();

        $this->warn("Skipped: {$reason} Its grants are not migrated.");
    }

    /**
     * Migrate `role_has_permissions` to `role_permissions` through the role
     * service, so guard parity is checked and each grant is reported.
     *
     * @param  array<int|string, \SineMacula\Laravel\Authorization\Models\Role>  $roleIdMap
     * @param  array<int|string, \SineMacula\Laravel\Authorization\Models\Permission>  $permissionIdMap
     * @param  bool  $dryRun
     * @param  array<string, int>  $counts
     * @return void
     *
     * @throws \Throwable
     */
    private function migrateRolePermissions(array $roleIdMap, array $permissionIdMap, bool $dryRun, array &$counts): void
    {
        foreach (DB::table('role_has_permissions')->get() as $row) {
            /** @var array{role_id: int|string, permission_id: int|string} $rolePermissionRow */
            $rolePermissionRow = (array) $row;
            $role              = $roleIdMap[$rolePermissionRow['role_id']]             ?? null;
            $permission        = $permissionIdMap[$rolePermissionRow['permission_id']] ?? null;

            if ($role === null || $permission === null) {
                continue;
            }

            if (!$dryRun) {
                $this->roles->grantPermission($role, $permission);
            }

            $counts['role_permissions']++;
        }
    }

    /**
     * Migrate one of Spatie's grant tables (`model_has_roles`,
     * `model_has_permissions`) through the grant service and return the number
     * of grants migrated. A grant whose role or permission was skipped is
     * skipped with it. Spatie's grants carry no scope, so each is imported
     * platform-wide, for every application. The grantee is named by Spatie's
     * `model_type` and `model_id`, so its class need not be loadable.
     *
     * @template TModel of \Illuminate\Database\Eloquent\Model
     *
     * @param  string  $source
     * @param  string  $column
     * @param  array<int|string, TModel>  $idMap
     * @param  bool  $dryRun
     * @param  \Closure(\SineMacula\Laravel\Authorization\Support\Reference, TModel): mixed  $grant
     * @return int
     */
    private function migrateGrants(string $source, string $column, array $idMap, bool $dryRun, \Closure $grant): int
    {
        $migrated = 0;

        foreach (DB::table($source)->get() as $row) {
            /** @var array<string, int|string> $spatieGrant */
            $spatieGrant = (array) $row;
            $target      = $idMap[$spatieGrant[$column]] ?? null;

            if ($target === null) {
                continue;
            }

            if (!$dryRun) {
                $grant(new Reference((string) $spatieGrant['model_type'], (string) $spatieGrant['model_id']), $target);
            }

            $migrated++;
        }

        return $migrated;
    }
}
