<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Console;

use Illuminate\Console\Command;
use Illuminate\Database\Connection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Authorization\Config\ModelClasses;
use SineMacula\Laravel\Authorization\Config\TableNames;
use SineMacula\Laravel\Authorization\Database\AuthorizationConnection;
use SineMacula\Laravel\Authorization\Enums\GrantOutcome;
use SineMacula\Laravel\Authorization\Exceptions\InvalidAuthorizationNameException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Services\GrantService;
use SineMacula\Laravel\Authorization\Services\PermissionService;
use SineMacula\Laravel\Authorization\Services\RoleService;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\TenantChain;

/**
 * Migrate data from Spatie's `laravel-permission` tables into this package's
 * schema.
 *
 * Reads Spatie's `roles`, `permissions`, `model_has_roles`,
 * `model_has_permissions` and `role_has_permissions` tables, under the names
 * and on the connection the options give (Spatie's defaults and the default
 * connection when left out), and writes each row through the management
 * services, so every role, permission and grant is validated and reported as
 * any other write here is, mapping column names (Spatie's `guard_name` becomes
 * `guard`) and generating UUIDs when Spatie used auto-increment IDs. Role and
 * permission names are checked against the models' name rule before they are
 * written; a name that fails it is reported and skipped together with its
 * grants, as is a permission name containing `*`, because `*` is a wildcard
 * here. This package's tables are written on its own connection
 * (`authorization.connection`), and the command refuses, before reading
 * anything, when a source table is one of them. The `--dry-run` flag reports
 * counts without writing.
 *
 * A platform role or permission of the same name and guard is reused, and a
 * grant already held with no expiry is left as it is, so a re-run carries on
 * where an earlier run stopped and reports those rows as already present. A
 * grant given an expiry since, or expired, is granted again without one. Two
 * Spatie rows that map to the same role or permission stop the import before
 * anything is written.
 *
 * The import runs in two steps. The roles, the permissions and the roles'
 * permissions are written first, in one transaction, which commits before any
 * grant is made: a failure there writes nothing. Then each Spatie grant is made
 * as a call of its own, in its own transaction, so the grant hooks of each run
 * before any lock the package takes for it, never under the locks of the rows
 * already imported. The grants are therefore not one atomic write: a grant that
 * fails, or that a hook refuses, stops the import, and the roles, permissions
 * and grants written before it stay; so does a grant that would leave someone
 * holding both roles of a pair already declared, refused with
 * `RoleExclusionConflictException`. Run the command outside any transaction of
 * your own, so each grant's own transaction is the outermost one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class MigrateSpatieCommand extends Command
{
    /** @var string The console command's name. */
    public const string NAME = 'authorization:migrate-spatie';

    /** @var list<string> The options naming Spatie's source tables. */
    private const array SOURCE_TABLE_OPTIONS = [
        'roles-table',
        'permissions-table',
        'role-has-permissions-table',
        'model-has-roles-table',
        'model-has-permissions-table',
    ];

    /** @var list<string> The keys of the package tables the import writes. */
    private const array TARGET_TABLES = ['roles', 'permissions', 'role_permissions', 'authorizable_roles', 'authorizable_permissions'];

    /** @var string The console command signature. */
    protected $signature = self::NAME . <<<'EOD'

                                    {--dry-run : Report counts without writing}
                                    {--connection= : The connection Spatie's tables are on (the default connection when left out)}
                                    {--roles-table=roles : Spatie's roles table}
                                    {--permissions-table=permissions : Spatie's permissions table}
                                    {--role-has-permissions-table=role_has_permissions : Spatie's role permissions table}
                                    {--model-has-roles-table=model_has_roles : Spatie's role grants table}
                                    {--model-has-permissions-table=model_has_permissions : Spatie's permission grants table}
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
        if (!$this->isSourceApartFromTarget() || !$this->verifySourceSchema() || !$this->verifyTargetSchema()) {
            return self::FAILURE;
        }

        /** @var bool $dryRun */
        $dryRun = (bool) $this->option('dry-run');

        if ($dryRun) {
            $this->info('Dry run — no data will be written.');
            $this->line('');
        }

        $counts = \array_fill_keys(self::TARGET_TABLES, ['rows' => 0, 'present' => 0]);

        $catalogue = function () use ($dryRun, &$counts): array {
            $roleIdMap       = $this->migrateRoles($dryRun, $counts);
            $permissionIdMap = $this->migratePermissions($dryRun, $counts);
            $this->migrateRolePermissions($roleIdMap, $permissionIdMap, $dryRun, $counts);

            return [$roleIdMap, $permissionIdMap];
        };

        [$roleIdMap, $permissionIdMap] = $dryRun ? $catalogue() : $this->target()->transaction($catalogue);

        // Each grant is a call of its own, made once the catalogue has
        // committed, so its grant hooks run before any lock the package takes
        // for it.
        $counts['authorizable_roles']       = $this->migrateGrants('model-has-roles-table', 'role_id', $roleIdMap, $dryRun, $this->grants->grantRole(...));
        $counts['authorizable_permissions'] = $this->migrateGrants('model-has-permissions-table', 'permission_id', $permissionIdMap, $dryRun, $this->grants->grantPermission(...));

        $this->renderMigrationSummary($counts, $dryRun);

        return self::SUCCESS;
    }

    /**
     * Render the post-migration summary table and the dry-run reminder when
     * applicable.
     *
     * @param  array<string, array<'present'|'rows', int>>  $counts
     * @param  bool  $dryRun
     * @return void
     */
    private function renderMigrationSummary(array $counts, bool $dryRun): void
    {
        $this->line('');
        $this->info('Migration summary:');
        $this->table(
            ['Target Table', 'Rows', 'Already Present'],
            \array_map(
                static fn (string $table, array $count): array => [$table, $count['rows'], $count['present']],
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
     * Determine whether every Spatie source table is apart from the package
     * tables the import writes, reporting the first that is one of them.
     *
     * @return bool
     */
    private function isSourceApartFromTarget(): bool
    {
        $connection = $this->source()->getName();

        if ($connection !== $this->target()->getName()) {
            return true;
        }

        $targets = \array_map(static fn (string $key): string => TableNames::get($key), self::TARGET_TABLES);

        foreach (self::SOURCE_TABLE_OPTIONS as $option) {
            $table = $this->sourceTable($option);

            if (\in_array($table, $targets, true)) {
                $this->error(
                    "Spatie source table '{$table}' is one of this package's tables on connection '{$connection}'. "
                    . "Pass --{$option} or --connection to name Spatie's table.",
                );

                return false;
            }
        }

        return true;
    }

    /**
     * Verify that all Spatie source tables exist.
     *
     * @return bool
     */
    private function verifySourceSchema(): bool
    {
        $schema = $this->source()->getSchemaBuilder();

        foreach (self::SOURCE_TABLE_OPTIONS as $option) {
            $table = $this->sourceTable($option);

            if (!$schema->hasTable($table)) {
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

        foreach (self::TARGET_TABLES as $key) {
            $table = TableNames::get($key);

            if (!$schema->hasTable($table)) {
                $this->error("Target table '{$table}' does not exist. Run the package migrations first.");

                return false;
            }
        }

        return true;
    }

    /**
     * Return the connection the package's tables live on, which the import
     * writes to and runs its transaction on.
     *
     * @return \Illuminate\Database\Connection
     */
    private function target(): Connection
    {
        /** @var \Illuminate\Database\Connection */
        return DB::connection(AuthorizationConnection::name());
    }

    /**
     * Return the connection Spatie's tables are read on.
     *
     * @return \Illuminate\Database\Connection
     */
    private function source(): Connection
    {
        /** @var string|null $name */
        $name = $this->option('connection');

        /** @var \Illuminate\Database\Connection */
        return DB::connection($name);
    }

    /**
     * Return the name of the Spatie table the option gives.
     *
     * @param  string  $option
     * @return string
     */
    private function sourceTable(string $option): string
    {
        /** @var string */
        return $this->option($option);
    }

    /**
     * Return the platform's row of the configured model with the name and
     * guard, which a re-run reuses, or null when there is none.
     *
     * @param  'permission'|'role'  $model
     * @param  string  $name
     * @param  string|null  $guard
     * @return \Illuminate\Database\Eloquent\Model|null
     */
    private static function platformRow(string $model, string $name, ?string $guard): ?Model
    {
        /** @var class-string<\Illuminate\Database\Eloquent\Model> $class */
        $class = ModelClasses::get($model);

        return TenantChain::whereNullTenant($class::query()->where('name', $name)->where('guard', $guard), 'tenant_type', 'tenant_id')->first();
    }

    /**
     * Migrate roles from Spatie's `roles` table through the role service, so
     * each is validated and reported as any role created here is, reusing the
     * platform's role of the same name and guard. A Spatie string id is kept;
     * an auto-increment one is replaced by a UUID. A dry run builds each new
     * role without saving it.
     *
     * @param  bool  $dryRun
     * @param  array<string, array<'present'|'rows', int>>  $counts
     * @return array<int|string, \SineMacula\Laravel\Authorization\Models\Role>
     *
     * @throws \Throwable
     */
    private function migrateRoles(bool $dryRun, array &$counts): array
    {
        $idMap   = [];
        $claimed = [];

        foreach ($this->source()->table($this->sourceTable('roles-table'))->get() as $row) {
            /** @var array{id: int|string, name: string, guard_name?: string|null} $roleRow */
            $roleRow = (array) $row;

            if (!Role::isValidAuthorizationName($roleRow['name'])) {
                $this->reportRefusedName('role', $roleRow['name']);

                continue;
            }

            $guard = $roleRow['guard_name'] ?? null;

            /** @var \SineMacula\Laravel\Authorization\Models\Role|null $existing */
            $existing = self::platformRow('role', $roleRow['name'], $guard);

            $idMap[$roleRow['id']] = $existing ?? ($dryRun
                ? new Role(['name' => $roleRow['name'], 'guard' => $guard])
                : $this->roles->create($roleRow['name'], $guard, id: self::keptId($roleRow['id'])));

            self::claim($claimed, 'role', $idMap[$roleRow['id']], $roleRow['id']);

            $counts['roles'][$existing === null ? 'rows' : 'present']++;
        }

        return $idMap;
    }

    /**
     * Migrate permissions from Spatie's `permissions` table through the
     * permission service, reusing and keeping ids as `migrateRoles()` does. A
     * dry run builds each new permission without saving it.
     *
     * @param  bool  $dryRun
     * @param  array<string, array<'present'|'rows', int>>  $counts
     * @return array<int|string, \SineMacula\Laravel\Authorization\Models\Permission>
     *
     * @throws \Throwable
     */
    private function migratePermissions(bool $dryRun, array &$counts): array
    {
        $idMap   = [];
        $claimed = [];

        foreach ($this->source()->table($this->sourceTable('permissions-table'))->get() as $row) {
            /** @var array{id: int|string, name: string, guard_name?: string|null} $permissionRow */
            $permissionRow = (array) $row;

            if (!$this->isImportablePermissionName($permissionRow['name'])) {
                continue;
            }

            $guard = $permissionRow['guard_name'] ?? null;

            /** @var \SineMacula\Laravel\Authorization\Models\Permission|null $existing */
            $existing = self::platformRow('permission', $permissionRow['name'], $guard);

            $idMap[$permissionRow['id']] = $existing ?? ($dryRun
                ? new Permission(['name' => $permissionRow['name'], 'guard' => $guard])
                : $this->permissions->create($permissionRow['name'], $guard, id: self::keptId($permissionRow['id'])));

            self::claim($claimed, 'permission', $idMap[$permissionRow['id']], $permissionRow['id']);

            $counts['permissions'][$existing === null ? 'rows' : 'present']++;
        }

        return $idMap;
    }

    /**
     * Record the role or permission a Spatie row maps to, refusing a second
     * Spatie row that maps to the same one, which would merge the two.
     *
     * @param  array<string, int|string>  $claimed
     * @param  'permission'|'role'  $kind
     * @param  \SineMacula\Laravel\Authorization\Models\Permission|\SineMacula\Laravel\Authorization\Models\Role  $row
     * @param  int|string  $spatieId
     * @return void
     *
     * @throws \UnexpectedValueException
     */
    private static function claim(array &$claimed, string $kind, Permission|Role $row, int|string $spatieId): void
    {
        $key = \json_encode([$row->name, $row->guard], \JSON_THROW_ON_ERROR);

        if (isset($claimed[$key])) {
            throw new \UnexpectedValueException("Spatie {$kind}s {$claimed[$key]} and {$spatieId} both map to {$kind} '{$row->name}' with guard '{$row->guard}'.");
        }

        $claimed[$key] = $spatieId;
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
     * @param  array<string, array<'present'|'rows', int>>  $counts
     * @return void
     *
     * @throws \Throwable
     */
    private function migrateRolePermissions(array $roleIdMap, array $permissionIdMap, bool $dryRun, array &$counts): void
    {
        foreach ($this->source()->table($this->sourceTable('role-has-permissions-table'))->get() as $row) {
            /** @var array{role_id: int|string, permission_id: int|string} $rolePermissionRow */
            $rolePermissionRow = (array) $row;
            $role              = $roleIdMap[$rolePermissionRow['role_id']]             ?? null;
            $permission        = $permissionIdMap[$rolePermissionRow['permission_id']] ?? null;

            if ($role === null || $permission === null) {
                continue;
            }

            $outcome = $dryRun ? null : $this->roles->grantPermission($role, $permission);

            $counts['role_permissions'][$outcome === GrantOutcome::UNCHANGED ? 'present' : 'rows']++;
        }
    }

    /**
     * Migrate one of Spatie's grant tables (`model_has_roles`,
     * `model_has_permissions`), named by the option given, through the grant
     * service and return the number of grants migrated and of those already
     * held. A grant whose role or permission was skipped is skipped with it.
     * Spatie's grants carry no scope, so each is imported platform-wide, for
     * every application. The grantee is named by Spatie's `model_type` and
     * `model_id`, so its class need not be loadable.
     *
     * @template TModel of \Illuminate\Database\Eloquent\Model
     *
     * @param  string  $option
     * @param  string  $column
     * @param  array<int|string, TModel>  $idMap
     * @param  bool  $dryRun
     * @param  \Closure(\SineMacula\Laravel\Authorization\Support\Reference, TModel): \SineMacula\Laravel\Authorization\Enums\GrantOutcome  $grant
     * @return array{rows: int, present: int}
     */
    private function migrateGrants(string $option, string $column, array $idMap, bool $dryRun, \Closure $grant): array
    {
        $migrated = ['rows' => 0, 'present' => 0];

        foreach ($this->source()->table($this->sourceTable($option))->get() as $row) {
            /** @var array<string, int|string> $spatieGrant */
            $spatieGrant = (array) $row;
            $target      = $idMap[$spatieGrant[$column]] ?? null;

            if ($target === null) {
                continue;
            }

            $outcome = $dryRun ? null : $grant(new Reference((string) $spatieGrant['model_type'], (string) $spatieGrant['model_id']), $target);

            $migrated[$outcome === GrantOutcome::UNCHANGED ? 'present' : 'rows']++;
        }

        return $migrated;
    }
}
