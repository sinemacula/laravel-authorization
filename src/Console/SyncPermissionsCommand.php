<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Console;

use Illuminate\Console\Command;
use SineMacula\Laravel\Authorization\Config\ConfigValidator;
use SineMacula\Laravel\Authorization\Console\Support\ActorOption;
use SineMacula\Laravel\Authorization\Console\Support\PermissionDiff;
use SineMacula\Laravel\Authorization\Console\Support\PermissionDiffBuilder;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\Operation;
use SineMacula\Laravel\Authorization\Support\OperationScope;
use SineMacula\Laravel\Authorization\Support\PermissionCatalogue;
use SineMacula\Laravel\Authorization\Support\PermissionDefinition;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Sync the platform's permission catalogue from the configured enums and
 * providers to the database.
 *
 * Reads every permission the enums in `authorization.permission_enums` and the
 * providers in `authorization.permission_providers` declare and compares them
 * with the platform's permission rows (tenant columns null). Within one
 * transaction on the package's connection it adds the permissions with no row
 * and updates the description and category of the rows that differ, through the
 * configured permission model, so its observers run. Rows no enum or provider
 * declares are reported as stale and left alone; with `--prune`, stale rows not
 * marked system are deleted through the model. A system row is never changed:
 * when stale, or declared with different metadata, it is reported as protected.
 * Tenant-owned permissions are never read or changed.
 *
 * The sync is one operation: every event its writes dispatch shares one
 * operation id and is dispatched once the transaction commits.
 * `--actor={morphType}:{key}` names the actor making the change, which those
 * events carry; without it the sync records no actor.
 *
 * Every row is listed with its action (`add`, `update`, `stale`, `prune`,
 * `protected` or `unchanged`), as a table or, with `--format=json`, as JSON.
 *
 * Exit codes: 0 on success; 1 when `--dry-run` finds a permission to add,
 * update or prune, so CI can detect drift; 2 on a fatal error (an invalid
 * catalogue or configuration, an unknown format, or a failed write, after which
 * nothing has been written).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class SyncPermissionsCommand extends Command
{
    /** @var int Exit code when a dry run finds something to change. */
    private const int EXIT_DRIFT = 1;

    /** @var int Exit code on a fatal error. */
    private const int EXIT_FATAL = 2;

    /** @var list<string> Accepted values of `--format`. */
    private const array FORMATS = ['table', 'json'];

    /** @var list<string> Every action a row can be listed with, in order. */
    private const array ACTIONS = ['add', 'update', 'stale', 'prune', 'protected', 'unchanged'];

    /** @var string The console command signature. */
    protected $signature = <<<'EOD'
        authorization:sync
                                    {--dry-run : Report what would change without writing}
                                    {--format=table : Output format: table or json}
                                    {--prune : Delete stale permissions that are not marked system}
                                    {--actor= : The actor making the change, in morphType:key format (e.g. user:1); none for system work}
        EOD;

    /** @var string The console command description. */
    protected $description = 'Sync the permission catalogue declared by the configured enums and providers to the database';

    /**
     * Execute the console command.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\PermissionCatalogue  $catalogue
     * @param  \SineMacula\Laravel\Authorization\Console\Support\PermissionDiffBuilder  $builder
     * @return int
     */
    public function handle(PermissionCatalogue $catalogue, PermissionDiffBuilder $builder): int
    {
        $format = $this->option('format');

        if (!\in_array($format, self::FORMATS, true)) {
            $this->error('Unknown format \'' . (\is_string($format) ? $format : '') . '\': expected \'table\' or \'json\'.');

            return self::EXIT_FATAL;
        }

        try {
            /** @var array<string, mixed> $config */
            $config = config('authorization', []);

            ConfigValidator::validate($config, $this->laravel);

            $entries = $this->entries($this->reconcile($catalogue->definitions(), $builder, ActorOption::parse($this->option('actor'))));
        } catch (\Throwable $exception) {
            $this->error('Nothing was synced: ' . $exception->getMessage());

            return self::EXIT_FATAL;
        }

        $format === 'json' ? $this->renderJson($entries) : $this->renderTable($entries);

        return $this->exitCode($entries);
    }

    /**
     * Compare the declared definitions with the platform rows and, unless this
     * is a dry run, apply the difference, all within one transaction on the
     * package's connection, as one operation for the given actor.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Support\PermissionDefinition>  $definitions
     * @param  \SineMacula\Laravel\Authorization\Console\Support\PermissionDiffBuilder  $builder
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $actor
     * @return \SineMacula\Laravel\Authorization\Console\Support\PermissionDiff
     *
     * @throws \Throwable
     */
    private function reconcile(array $definitions, PermissionDiffBuilder $builder, ?Reference $actor): PermissionDiff
    {
        $model = $this->permissionModel();

        /** @var \SineMacula\Laravel\Authorization\Console\Support\PermissionDiff */
        return OperationScope::run(Operation::begin($actor), function () use ($definitions, $builder, $model): PermissionDiff {
            /** @var list<\SineMacula\Laravel\Authorization\Models\Permission> $rows */
            $rows = $model->newQueryWithoutScope(TenantScope::class)
                ->whereNull('tenant_type')
                ->whereNull('tenant_id')
                ->get()
                ->all();

            $diff = $builder->build($definitions, $rows);

            if (!$this->isDryRun()) {
                $this->apply($diff, $model);
            }

            return $diff;
        });
    }

    /**
     * Write the difference: insert the permissions to add, update the rows
     * whose metadata differs and, when pruning, delete the stale rows, each
     * through the permission model so its observers run.
     *
     * @param  \SineMacula\Laravel\Authorization\Console\Support\PermissionDiff  $diff
     * @param  \SineMacula\Laravel\Authorization\Models\Permission  $model
     * @return void
     */
    private function apply(PermissionDiff $diff, Permission $model): void
    {
        foreach ($diff->add as $definition) {
            $model->newInstance([
                'name'        => $definition->name,
                'guard'       => $definition->guard,
                'description' => $definition->description,
                'category'    => $definition->category,
            ])->save();
        }

        foreach ($diff->update as $pair) {
            $pair['row']->fill([
                'description' => $pair['definition']->description,
                'category'    => $pair['definition']->category,
            ])->save();
        }

        if (!$this->isPruning()) {
            return;
        }

        foreach ($diff->stale as $row) {
            $row->delete();
        }
    }

    /**
     * List every row of the diff with its action, in the order the actions are
     * listed.
     *
     * @param  \SineMacula\Laravel\Authorization\Console\Support\PermissionDiff  $diff
     * @return list<array{action: string, name: string, guard: string|null, description: string|null, category: string|null}>
     */
    private function entries(PermissionDiff $diff): array
    {
        $staleAction = $this->isPruning() ? 'prune' : 'stale';

        return [
            ...\array_map(static fn (PermissionDefinition $definition): array => self::entry('add', $definition), $diff->add),
            ...\array_map(static fn (array $pair): array => self::entry('update', $pair['definition']), $diff->update),
            ...\array_map(static fn (Permission $row): array => self::entry($staleAction, $row), $diff->stale),
            ...\array_map(static fn (Permission $row): array => self::entry('protected', $row), $diff->protected),
            ...\array_map(static fn (Permission $row): array => self::entry('unchanged', $row), $diff->unchanged),
        ];
    }

    /**
     * Describe a definition or a row with the given action.
     *
     * @param  string  $action
     * @param  \SineMacula\Laravel\Authorization\Models\Permission|\SineMacula\Laravel\Authorization\Support\PermissionDefinition  $permission
     * @return array{action: string, name: string, guard: string|null, description: string|null, category: string|null}
     */
    private static function entry(string $action, Permission|PermissionDefinition $permission): array
    {
        return [
            'action'      => $action,
            'name'        => $permission->name,
            'guard'       => $permission->guard,
            'description' => $permission->description,
            'category'    => $permission->category,
        ];
    }

    /**
     * Render the entries as a table, followed by a summary line.
     *
     * @param  list<array{action: string, name: string, guard: string|null, description: string|null, category: string|null}>  $entries
     * @return void
     */
    private function renderTable(array $entries): void
    {
        $this->table(
            ['Action', 'Name', 'Guard', 'Category', 'Description'],
            \array_map(static fn (array $entry): array => [
                $entry['action'],
                $entry['name'],
                $entry['guard']       ?? '(any)',
                $entry['category']    ?? '',
                $entry['description'] ?? '',
            ], $entries),
        );

        $summary = [];

        foreach (self::summary($entries) as $action => $count) {
            $summary[] = "{$action}: {$count}";
        }

        $this->line(($this->isDryRun() ? 'Dry run, nothing was written. ' : '') . \implode(', ', $summary) . '.');
    }

    /**
     * Render the entries as JSON, with the run's mode and a count per action.
     *
     * @param  list<array{action: string, name: string, guard: string|null, description: string|null, category: string|null}>  $entries
     * @return void
     *
     * @throws \JsonException
     */
    private function renderJson(array $entries): void
    {
        $this->line(\json_encode([
            'dry_run'     => $this->isDryRun(),
            'prune'       => $this->isPruning(),
            'summary'     => self::summary($entries),
            'permissions' => $entries,
        ], \JSON_THROW_ON_ERROR | \JSON_PRETTY_PRINT | \JSON_UNESCAPED_SLASHES));
    }

    /**
     * Count the entries of each action, every action included.
     *
     * @param  list<array{action: string, name: string, guard: string|null, description: string|null, category: string|null}>  $entries
     * @return array<string, int>
     */
    private static function summary(array $entries): array
    {
        $summary = \array_fill_keys(self::ACTIONS, 0);

        foreach ($entries as $entry) {
            $summary[$entry['action']]++;
        }

        return $summary;
    }

    /**
     * Return the exit code: drift when a dry run finds a permission to add,
     * update or prune, success otherwise.
     *
     * @param  list<array{action: string, name: string, guard: string|null, description: string|null, category: string|null}>  $entries
     * @return int
     */
    private function exitCode(array $entries): int
    {
        $summary = self::summary($entries);
        $changes = $summary['add'] + $summary['update'] + $summary['prune'];

        return $this->isDryRun() && $changes > 0 ? self::EXIT_DRIFT : self::SUCCESS;
    }

    /**
     * Return an instance of the configured permission model.
     *
     * @return \SineMacula\Laravel\Authorization\Models\Permission
     */
    private function permissionModel(): Permission
    {
        /** @var class-string<\SineMacula\Laravel\Authorization\Models\Permission> $class */
        $class = config('authorization.models.permission', Permission::class);

        return new $class;
    }

    /**
     * Determine whether this run only reports.
     *
     * @return bool
     */
    private function isDryRun(): bool
    {
        return $this->option('dry-run') === true;
    }

    /**
     * Determine whether this run deletes stale rows.
     *
     * @return bool
     */
    private function isPruning(): bool
    {
        return $this->option('prune') === true;
    }
}
