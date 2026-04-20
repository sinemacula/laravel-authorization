<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Console;

use Carbon\CarbonImmutable;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Console\Support\PermissionDiff;
use SineMacula\Laravel\Authorization\Console\Support\PermissionDiffBuilder;
use SineMacula\Laravel\Authorization\Console\Support\PermissionEnumWalker;
use SineMacula\Laravel\Authorization\Console\Support\PermissionTuple;
use SineMacula\Laravel\Authorization\Contracts\PermissionEnum;
use SineMacula\Laravel\Authorization\Events\Permission\Deprecated as PermissionDeprecated;
use SineMacula\Laravel\Authorization\Events\Permission\Reinstated as PermissionReinstated;
use SineMacula\Laravel\Authorization\Exceptions\InvalidPermissionAttributeException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;

/**
 * Project the permission enum catalogue into the `permissions` table.
 *
 * Walks every class in `authorization.permission_enums`, expands each case into
 * one `(name, guard)` tuple per configured guard, and reconciles the resulting
 * set against the current global rows via the pure `PermissionDiffBuilder`. The
 * six diff buckets (add, update, reinstate, retire, protected, unchanged) drive
 * the apply phase: inserts, metadata updates, `deprecated_at` clears,
 * `deprecated_at` stamps (or hard deletes under `--force-delete`), and no-ops
 * respectively.
 *
 * Flags:
 *
 * - `--dry-run` — compute and report the diff without writing. Exits with code
 *   1 when drift exists (`add`/`update`/`reinstate`/`retire` non-empty);
 *   `protected` and `unchanged` are not drift.
 * - `--format=table|json` — swap the stdout renderer. JSON output includes a
 *   top-level `dryRun` flag so pipelines can branch.
 * - `--force-delete` — hard-delete retired rows instead of stamping
 *   `deprecated_at`. `is_system` rows still surface in the `protected` bucket
 *   and are never touched.
 *
 * Role-permission pivots are never detached by sync; the `retire` count and the
 * pre-computed pivot reference count are reported so the operator can decide
 * when to prune.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
class SyncPermissionsCommand extends Command
{
    /** @var int Drift found under `--dry-run`. */
    private const int EXIT_DRIFT = 1;

    /** @var int Fatal error (bad config, bad enum, DB failure). */
    private const int EXIT_FATAL = 2;

    /** @var string Output format flag — structured JSON for pipelines. */
    private const string FORMAT_JSON = 'json';

    /** @var string Output format flag — human-readable table. */
    private const string FORMAT_TABLE = 'table';

    /** @var string The console command signature. */
    protected $signature = 'authorization:sync '
        . '{--dry-run : Compute and report the diff without writing to the database} '
        . '{--format=table : Output format; one of `table` or `json`} '
        . '{--force-delete : Hard-delete retired rows instead of stamping deprecated_at}';

    /** @var string The console command description. */
    protected $description = 'Sync the permission catalogue from configured enums to the database';

    /**
     * Create a new command instance.
     *
     * @param  \SineMacula\Laravel\Authorization\Console\Support\PermissionEnumWalker  $walker
     * @param  \SineMacula\Laravel\Authorization\Console\Support\PermissionDiffBuilder  $builder
     * @param  \SineMacula\Laravel\Authorization\Cache\ResolutionCache  $cache
     */
    public function __construct(

        /** Walker that flattens configured enums into `(name, guard)` tuples. */
        private readonly PermissionEnumWalker $walker,

        /** Diff builder that compares the walked tuples against the database. */
        private readonly PermissionDiffBuilder $builder,

        /** Resolution cache flushed when the sync mutates the catalogue. */
        private readonly ResolutionCache $cache,

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
        /** @var array<string, mixed>|bool|float|int|string|null $rawFormat */
        $rawFormat = $this->option('format');
        $format    = is_string($rawFormat) ? $rawFormat : '';

        if (!in_array($format, [self::FORMAT_TABLE, self::FORMAT_JSON], true)) {
            $this->error("Invalid --format '{$format}'. Expected 'table' or 'json'.");

            return self::EXIT_FATAL;
        }

        $dryRun      = (bool) $this->option('dry-run');
        $forceDelete = (bool) $this->option('force-delete');

        try {
            $enumClasses = $this->loadEnumClasses();
            $tuples      = $this->walker->walk($enumClasses);
            $rows        = $this->loadCurrentRows();
            $refCount    = $this->countRoleReferences($tuples, $rows);
            $diff        = $this->builder->build($tuples, $rows, $refCount);

            if (!$dryRun) {
                $this->applyDiff($diff, $forceDelete);
                $this->cache->flush();
            }
        } catch (InvalidPermissionAttributeException $exception) {
            $this->error($exception->getMessage());

            return self::EXIT_FATAL;
        }

        $this->render($diff, $dryRun, $format);

        return $this->resolveExitCode($diff, $dryRun);
    }

    /**
     * Load the configured permission enum class list, filtering out anything
     * that failed to materialise as a valid backed string enum. The
     * `ConfigValidator` already ran at boot; this filter exists so a
     * command-time config swap does not blow up the walker with a typeerror.
     *
     * @return list<class-string<\SineMacula\Laravel\Authorization\Contracts\PermissionEnum>>
     */
    private function loadEnumClasses(): array
    {
        /** @var array<int|string, mixed> $raw */
        $raw = (array) config('authorization.permission_enums', []);

        $classes = [];

        foreach ($raw as $candidate) {
            if (!is_string($candidate) || $candidate === '') {
                continue;
            }

            if (!is_subclass_of($candidate, PermissionEnum::class)) {
                continue;
            }

            $classes[] = $candidate;
        }

        return $classes;
    }

    /**
     * Load every global (`tenant_id IS NULL`) permission row, including
     * deprecated ones. Deprecated rows must participate in the diff so the
     * reinstate bucket can match them — with the default scope applied they
     * would look like "not in DB" and collide on the unique index when add
     * fired.
     *
     * The tenant scope is explicitly dropped: a tenant-resolved test context
     * would otherwise scope to the current tenant and hide global rows,
     * producing phantom adds.
     *
     * @return list<\SineMacula\Laravel\Authorization\Models\Permission>
     */
    private function loadCurrentRows(): array
    {
        // @phpstan-ignore staticMethod.dynamicCall
        $rows = Permission::withDeprecated()
            ->withoutGlobalScope(TenantScope::class)
            ->whereNull('tenant_id')
            ->get()
            ->all();

        return array_values($rows);
    }

    /**
     * Count role-permission pivot rows referencing any row that would land in
     * the retire bucket. Runs once before the diff builder so the builder can
     * surface the count on its own `PermissionDiff` without re-walking the
     * rows.
     *
     * Replicates the retire-candidate predicate the diff builder applies
     * internally — any row whose `(name, guard)` is not in the tuple set and
     * that is not `is_system` — to keep the count in sync with the bucket the
     * operator eventually sees.
     *
     * @param  list<\SineMacula\Laravel\Authorization\Console\Support\PermissionTuple>  $tuples
     * @param  list<\SineMacula\Laravel\Authorization\Models\Permission>  $rows
     * @return int
     */
    private function countRoleReferences(array $tuples, array $rows): int
    {
        $tupleKeys = [];

        foreach ($tuples as $tuple) {
            $tupleKeys[$this->compositeKey($tuple->name, $tuple->guard)] = true;
        }

        $candidateIds = [];

        foreach ($rows as $row) {
            if (isset($tupleKeys[$this->compositeKey($row->name, $row->guard)])) {
                continue;
            }

            if ($row->is_system) {
                continue;
            }

            /** @var string $id */
            $id             = $row->getKey();
            $candidateIds[] = $id;
        }

        if ($candidateIds === []) {
            return 0;
        }

        /** @var string $pivotTable */
        $pivotTable = config('authorization.tables.role_permissions', 'role_permissions');

        return DB::table($pivotTable)
            ->whereIn('permission_id', $candidateIds)
            ->count();
    }

    /**
     * Apply the computed diff — inserts, updates, reinstates, and retires —
     * inside a single transaction so a mid-apply failure leaves the DB in a
     * consistent state.
     *
     * @param  \SineMacula\Laravel\Authorization\Console\Support\PermissionDiff  $diff
     * @param  bool  $forceDelete
     * @return void
     */
    private function applyDiff(PermissionDiff $diff, bool $forceDelete): void
    {
        DB::transaction(function () use ($diff, $forceDelete): void {
            foreach ($diff->add as $tuple) {
                $this->applyAdd($tuple);
            }

            foreach ($diff->update as $pair) {
                $this->applyUpdate($pair['row'], $pair['tuple']);
            }

            foreach ($diff->reinstate as $pair) {
                $this->applyReinstate($pair['row'], $pair['tuple']);
            }

            foreach ($diff->retire as $row) {
                $this->applyRetire($row, $forceDelete);
            }
        });
    }

    /**
     * Insert a fresh permission row for an unmatched tuple. The observer fires
     * `Permission\Created` automatically on save.
     *
     * @param  \SineMacula\Laravel\Authorization\Console\Support\PermissionTuple  $tuple
     * @return void
     */
    private function applyAdd(PermissionTuple $tuple): void
    {
        Permission::create([
            'name'        => $tuple->name,
            'guard'       => $tuple->guard,
            'description' => $tuple->description,
            'category'    => $tuple->category,
            'is_system'   => false,
            'tenant_type' => null,
            'tenant_id'   => null,
        ]);
    }

    /**
     * Refresh metadata on a matched row whose description or category drifted
     * from its tuple. The observer fires `Permission\Updated` automatically on
     * save.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission  $row
     * @param  \SineMacula\Laravel\Authorization\Console\Support\PermissionTuple  $tuple
     * @return void
     */
    private function applyUpdate(Permission $row, PermissionTuple $tuple): void
    {
        $row->description = $tuple->description;
        $row->category    = $tuple->category;
        $row->save();
    }

    /**
     * Clear `deprecated_at` and refresh metadata on a previously retired row
     * that re-appeared in the enum catalogue. Dispatches
     * `Permission\Reinstated` in addition to the observer's
     * `Permission\Updated` so audit consumers can distinguish lifecycle
     * transitions from ordinary metadata drift.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission  $row
     * @param  \SineMacula\Laravel\Authorization\Console\Support\PermissionTuple  $tuple
     * @return void
     */
    private function applyReinstate(Permission $row, PermissionTuple $tuple): void
    {
        $row->deprecated_at = null;
        $row->description   = $tuple->description;
        $row->category      = $tuple->category;
        $row->save();

        Event::dispatch(new PermissionReinstated($row));
    }

    /**
     * Retire a row the enum no longer contains. Default behaviour stamps
     * `deprecated_at` and dispatches `Permission\Deprecated` on top of the
     * observer's `Permission\Updated`; `--force-delete` hard-deletes the row
     * and relies on the observer's `Permission\Deleted`.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission  $row
     * @param  bool  $forceDelete
     * @return void
     */
    private function applyRetire(Permission $row, bool $forceDelete): void
    {
        if ($forceDelete) {
            $row->delete();

            return;
        }

        $row->deprecated_at = CarbonImmutable::now();
        $row->save();

        Event::dispatch(new PermissionDeprecated($row));
    }

    /**
     * Route to the configured renderer.
     *
     * @param  \SineMacula\Laravel\Authorization\Console\Support\PermissionDiff  $diff
     * @param  bool  $dryRun
     * @param  string  $format
     * @return void
     */
    private function render(PermissionDiff $diff, bool $dryRun, string $format): void
    {
        if ($format === self::FORMAT_JSON) {
            $this->renderJson($diff, $dryRun);

            return;
        }

        $this->renderTable($diff, $dryRun);
    }

    /**
     * Render the diff as a pair of tables — a summary with one row per bucket
     * plus a detail listing when any bucket is non-empty.
     *
     * @param  \SineMacula\Laravel\Authorization\Console\Support\PermissionDiff  $diff
     * @param  bool  $dryRun
     * @return void
     */
    private function renderTable(PermissionDiff $diff, bool $dryRun): void
    {
        if ($dryRun) {
            $this->info('DRY RUN — no changes were written to the database.');
        }

        $this->table(
            ['Bucket', 'Count'],
            [
                ['Added', (string) count($diff->add)],
                ['Updated', (string) count($diff->update)],
                ['Reinstated', (string) count($diff->reinstate)],
                ['Retired', (string) count($diff->retire)],
                ['Protected', (string) count($diff->protected)],
                ['Unchanged', (string) count($diff->unchanged)],
                ['Role references on retired', (string) $diff->roleReferencesCount],
            ],
        );

        $details = $this->collectDetailRows($diff);

        if ($details !== []) {
            $this->table(['Name', 'Guard', 'Action'], $details);
        }
    }

    /**
     * Build the per-row detail rows shared by the table renderer.
     *
     * @param  \SineMacula\Laravel\Authorization\Console\Support\PermissionDiff  $diff
     * @return list<array{0: string, 1: string, 2: string}>
     */
    private function collectDetailRows(PermissionDiff $diff): array
    {
        $rows = [];

        foreach ($diff->add as $tuple) {
            $rows[] = [$tuple->name, $this->renderGuard($tuple->guard), 'add'];
        }

        foreach ($diff->update as $pair) {
            $rows[] = [$pair['tuple']->name, $this->renderGuard($pair['tuple']->guard), 'update'];
        }

        foreach ($diff->reinstate as $pair) {
            $rows[] = [$pair['tuple']->name, $this->renderGuard($pair['tuple']->guard), 'reinstate'];
        }

        foreach ($diff->retire as $row) {
            $rows[] = [$row->name, $this->renderGuard($row->guard), 'retire'];
        }

        foreach ($diff->protected as $row) {
            $rows[] = [$row->name, $this->renderGuard($row->guard), 'protected'];
        }

        return $rows;
    }

    /**
     * Render the diff as pretty-printed JSON with a `dryRun` flag so pipelines
     * can branch on the mutating vs reporting mode.
     *
     * @param  \SineMacula\Laravel\Authorization\Console\Support\PermissionDiff  $diff
     * @param  bool  $dryRun
     * @return void
     */
    private function renderJson(PermissionDiff $diff, bool $dryRun): void
    {
        $payload = [
            'dryRun'  => $dryRun,
            'summary' => [
                'add'            => count($diff->add),
                'update'         => count($diff->update),
                'reinstate'      => count($diff->reinstate),
                'retire'         => count($diff->retire),
                'protected'      => count($diff->protected),
                'unchanged'      => count($diff->unchanged),
                'roleReferences' => $diff->roleReferencesCount,
            ],
            'changes' => [
                'add'       => array_map(fn (PermissionTuple $t): array => $this->describeTuple($t, 'add'), $diff->add),
                'update'    => array_map(fn (array $p): array => $this->describeTuple($p['tuple'], 'update'), $diff->update),
                'reinstate' => array_map(fn (array $p): array => $this->describeTuple($p['tuple'], 'reinstate'), $diff->reinstate),
                'retire'    => array_map(fn (Permission $r): array => $this->describeRow($r, 'retire'), $diff->retire),
                'protected' => array_map(fn (Permission $r): array => $this->describeRow($r, 'protected'), $diff->protected),
            ],
        ];

        $this->line((string) json_encode($payload, \JSON_PRETTY_PRINT | \JSON_UNESCAPED_SLASHES));
    }

    /**
     * Describe a tuple for the JSON renderer.
     *
     * @param  \SineMacula\Laravel\Authorization\Console\Support\PermissionTuple  $tuple
     * @param  string  $action
     * @return array{name: string, guard: string|null, action: string}
     */
    private function describeTuple(PermissionTuple $tuple, string $action): array
    {
        return [
            'name'   => $tuple->name,
            'guard'  => $tuple->guard,
            'action' => $action,
        ];
    }

    /**
     * Describe a row for the JSON renderer.
     *
     * @param  \SineMacula\Laravel\Authorization\Models\Permission  $row
     * @param  string  $action
     * @return array{name: string, guard: string|null, action: string}
     */
    private function describeRow(Permission $row, string $action): array
    {
        return [
            'name'   => $row->name,
            'guard'  => $row->guard,
            'action' => $action,
        ];
    }

    /**
     * Render a guard slot for the table output, substituting a human-readable
     * sentinel for the guard-agnostic null.
     *
     * @param  string|null  $guard
     * @return string
     */
    private function renderGuard(?string $guard): string
    {
        return $guard ?? '(any)';
    }

    /**
     * Compose a match key equivalent to the one the diff builder uses
     * internally so the pre-diff retire-candidate lookup agrees with the bucket
     * assignment.
     *
     * @param  string  $name
     * @param  string|null  $guard
     * @return string
     */
    private function compositeKey(string $name, ?string $guard): string
    {
        $normalisedGuard = $guard === null || $guard === '' ? '' : $guard;

        return $name . "\0" . $normalisedGuard;
    }

    /**
     * Translate the diff and the run mode into an exit code per the spec — zero
     * for a clean run (or a dry-run with no drift), `EXIT_DRIFT` for a dry-run
     * that surfaced any mutating bucket, zero again for a successful live run.
     *
     * @param  \SineMacula\Laravel\Authorization\Console\Support\PermissionDiff  $diff
     * @param  bool  $dryRun
     * @return int
     */
    private function resolveExitCode(PermissionDiff $diff, bool $dryRun): int
    {
        if (!$dryRun) {
            return self::SUCCESS;
        }

        $driftCount = count($diff->add)
            + count($diff->update)
            + count($diff->reinstate)
            + count($diff->retire);

        return $driftCount > 0 ? self::EXIT_DRIFT : self::SUCCESS;
    }
}
