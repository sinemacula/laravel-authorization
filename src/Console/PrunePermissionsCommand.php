<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authorization\Console;

use Carbon\CarbonImmutable;
use Illuminate\Console\Command;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;

/**
 * Detach pivots and hard-delete deprecated permission rows.
 *
 * Follow-up to `authorization:sync`, run on the operator's own
 * cadence once they are comfortable that the soft-retired rows
 * (`deprecated_at IS NOT NULL`) are no longer needed. The command
 * loads every deprecated, non-system, global row matching the
 * optional `--before` timestamp filter, detaches its role and
 * identity pivot attachments, and calls `delete()` on the Eloquent
 * model so the observer's `Permission\Deleted` event fires.
 *
 * Flags:
 *
 * - `--before=<ISO-8601>` — only prune rows whose `deprecated_at`
 *   is at or before the supplied instant. Any valid ISO-8601
 *   string is accepted; parsing is delegated to `CarbonImmutable`.
 * - `--dry-run` — compute the candidate set and report without
 *   touching the database. Always exits zero, including when the
 *   set is empty — prune is advisory, not a drift check.
 * - `--format=table|json` — stdout renderer, mirroring the sync
 *   command. JSON output carries a `dryRun` flag so pipelines can
 *   branch on the mutating vs reporting mode.
 *
 * `is_system = true` rows are never touched — the filter on the
 * candidate query is the single source of truth for that
 * protection; the per-row apply path does not re-check it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
class PrunePermissionsCommand extends Command
{
    /** @var int Fatal error (unparseable `--before`, invalid format, DB failure). */
    private const int EXIT_FATAL = 2;

    /** @var string Output format flag — structured JSON for pipelines. */
    private const string FORMAT_JSON = 'json';

    /** @var string Output format flag — human-readable table. */
    private const string FORMAT_TABLE = 'table';

    /** @var string The console command signature. */
    protected $signature = <<<'EOD'
        authorization:prune-deprecated
                                    {--before= : ISO-8601 timestamp; prune only rows deprecated at or before this instant}
                                    {--dry-run : Compute and report the prune set without touching the database}
                                    {--format=table : Output format; one of `table` or `json`}
        EOD;

    /** @var string The console command description. */
    protected $description = 'Detach pivots and hard-delete deprecated permission rows';

    /**
     * Create a new command instance.
     *
     * @param  \SineMacula\Laravel\Authorization\Cache\ResolutionCache  $cache
     */
    public function __construct(
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
        $format    = \is_string($rawFormat) ? $rawFormat : '';

        if (!\in_array($format, [self::FORMAT_TABLE, self::FORMAT_JSON], true)) {
            $this->error("Invalid --format '{$format}'. Expected 'table' or 'json'.");

            return self::EXIT_FATAL;
        }

        $before = $this->resolveBefore();

        if ($before === false) {
            return self::EXIT_FATAL;
        }

        $dryRun     = (bool) $this->option('dry-run');
        $candidates = $this->loadCandidates($before);
        $report     = $this->describeCandidates($candidates);

        if (!$dryRun) {
            $this->applyPrune($candidates);
            $this->cache->flush();
        }

        $this->render($report, $dryRun, $format);

        return self::SUCCESS;
    }

    /**
     * Resolve the optional `--before` option into a `CarbonImmutable`,
     * or return `null` when omitted. On an unparseable value the
     * method emits the error and returns `false` so the caller exits
     * fatal — the explicit sentinel keeps the signature honest for
     * PHPStan without a throw/catch dance in `handle()`.
     *
     * @return \Carbon\CarbonImmutable|false|null
     */
    private function resolveBefore(): CarbonImmutable|false|null
    {
        /** @var array<string, mixed>|bool|float|int|string|null $raw */
        $raw = $this->option('before');

        if (!\is_string($raw) || $raw === '') {
            return null;
        }

        try {
            return CarbonImmutable::parse($raw);
        } catch (\Throwable $exception) {
            $this->error("Invalid --before '{$raw}': {$exception->getMessage()}");

            return false;
        }
    }

    /**
     * Load every candidate permission row — deprecated, non-system,
     * global (tenant-null), optionally filtered by `--before`. The
     * tenant scope is explicitly dropped so a tenant-resolved test
     * context does not hide global rows; the `ExcludesDeprecatedScope`
     * is dropped via `withDeprecated()` so deprecated rows actually
     * surface.
     *
     * @param  \Carbon\CarbonImmutable|null  $before
     * @return \Illuminate\Database\Eloquent\Collection<int, \SineMacula\Laravel\Authorization\Models\Permission>
     */
    private function loadCandidates(?CarbonImmutable $before): Collection
    {
        // @phpstan-ignore staticMethod.dynamicCall, staticMethod.dynamicCall, staticMethod.dynamicCall
        $query = Permission::withDeprecated()
            ->withoutGlobalScope(TenantScope::class)
            ->whereNull('tenant_id')
            ->whereNotNull('deprecated_at')
            ->where('is_system', false);

        if ($before !== null) {
            $query->where('deprecated_at', '<=', $before);
        }

        /** @var \Illuminate\Database\Eloquent\Collection<int, \SineMacula\Laravel\Authorization\Models\Permission> */
        return $query->get();
    }

    /**
     * Walk the candidate rows once and attach their per-row pivot
     * counts so the renderer and the apply phase share a single view
     * of the prune set. Counting up-front also makes the dry-run
     * summary accurate without a second query per row.
     *
     * @param  \Illuminate\Database\Eloquent\Collection<int, \SineMacula\Laravel\Authorization\Models\Permission>  $candidates
     * @return list<array{row: \SineMacula\Laravel\Authorization\Models\Permission, roleCount: int, identityCount: int}>
     */
    private function describeCandidates(Collection $candidates): array
    {
        $rolePivot     = $this->rolePermissionsTable();
        $identityPivot = $this->authorizablePermissionsTable();

        $report = [];

        foreach ($candidates as $row) {
            /** @var string $id */
            $id = $row->getKey();

            $report[] = [
                'row'           => $row,
                'roleCount'     => DB::table($rolePivot)->where('permission_id', $id)->count(),
                'identityCount' => DB::table($identityPivot)->where('permission_id', $id)->count(),
            ];
        }

        return $report;
    }

    /**
     * Detach pivots and delete each candidate inside a single
     * transaction so a mid-apply failure leaves the DB consistent.
     * The role pivot is detached via the Eloquent relation; the
     * identity pivot has no inverse relation on `Permission`, so
     * attached rows are cleared through a raw `DB::table()` delete
     * against the configured pivot table. `$row->delete()` drives
     * the observer-fired `Permission\Deleted` event.
     *
     * @param  \Illuminate\Database\Eloquent\Collection<int, \SineMacula\Laravel\Authorization\Models\Permission>  $candidates
     * @return void
     */
    private function applyPrune(Collection $candidates): void
    {
        if ($candidates->isEmpty()) {
            return;
        }

        $identityPivot = $this->authorizablePermissionsTable();

        DB::transaction(function () use ($candidates, $identityPivot): void {
            foreach ($candidates as $row) {
                $row->roles()->detach();

                DB::table($identityPivot)->where('permission_id', $row->getKey())->delete();

                $row->delete();
            }
        });
    }

    /**
     * Route to the configured renderer.
     *
     * @param  list<array{row: \SineMacula\Laravel\Authorization\Models\Permission, roleCount: int, identityCount: int}>  $report
     * @param  bool  $dryRun
     * @param  string  $format
     * @return void
     */
    private function render(array $report, bool $dryRun, string $format): void
    {
        if ($format === self::FORMAT_JSON) {
            $this->renderJson($report, $dryRun);

            return;
        }

        $this->renderTable($report, $dryRun);
    }

    /**
     * Render the prune set as an action/count summary plus a per-row
     * detail listing when there are any candidates.
     *
     * @param  list<array{row: \SineMacula\Laravel\Authorization\Models\Permission, roleCount: int, identityCount: int}>  $report
     * @param  bool  $dryRun
     * @return void
     */
    private function renderTable(array $report, bool $dryRun): void
    {
        if ($dryRun) {
            $this->info('DRY RUN — no changes were written to the database.');
        }

        $totals = $this->tally($report);

        $this->table(
            ['Action', 'Count'],
            [
                ['Deprecated rows considered', (string) $totals['considered']],
                ['Role pivots detached', (string) $totals['roleCount']],
                ['Identity pivots detached', (string) $totals['identityCount']],
                ['Rows deleted', (string) ($dryRun ? 0 : $totals['considered'])],
            ],
        );

        if ($report === []) {
            return;
        }

        $rows = [];

        foreach ($report as $entry) {
            $rows[] = [
                $entry['row']->name,
                $this->renderGuard($entry['row']->guard),
                $this->renderDeprecatedAt($entry['row']->deprecated_at),
                (string) $entry['roleCount'],
                (string) $entry['identityCount'],
            ];
        }

        $this->table(['Name', 'Guard', 'Deprecated at', 'Roles', 'Identities'], $rows);
    }

    /**
     * Render the prune set as pretty-printed JSON — matches the sync
     * command's payload shape (top-level `dryRun` + `summary` +
     * per-row detail) so downstream tooling can consume both outputs
     * through a shared parser.
     *
     * @param  list<array{row: \SineMacula\Laravel\Authorization\Models\Permission, roleCount: int, identityCount: int}>  $report
     * @param  bool  $dryRun
     * @return void
     */
    private function renderJson(array $report, bool $dryRun): void
    {
        $totals = $this->tally($report);

        $payload = [
            'dryRun'  => $dryRun,
            'summary' => [
                'considered'    => $totals['considered'],
                'roleCount'     => $totals['roleCount'],
                'identityCount' => $totals['identityCount'],
                'deleted'       => $dryRun ? 0 : $totals['considered'],
            ],
            'candidates' => \array_map(fn (array $entry): array => $this->describeEntry($entry), $report),
        ];

        $this->line((string) \json_encode($payload, \JSON_PRETTY_PRINT | \JSON_UNESCAPED_SLASHES));
    }

    /**
     * Collapse the per-row report into the summary counts used by
     * both renderers — kept private so the two formats stay in
     * lock-step without sharing an intermediate DTO with any caller.
     *
     * @param  list<array{row: \SineMacula\Laravel\Authorization\Models\Permission, roleCount: int, identityCount: int}>  $report
     * @return array{considered: int, roleCount: int, identityCount: int}
     */
    private function tally(array $report): array
    {
        $roleCount     = 0;
        $identityCount = 0;

        foreach ($report as $entry) {
            $roleCount     += $entry['roleCount'];
            $identityCount += $entry['identityCount'];
        }

        return [
            'considered'    => \count($report),
            'roleCount'     => $roleCount,
            'identityCount' => $identityCount,
        ];
    }

    /**
     * Describe a single candidate entry for the JSON renderer.
     *
     * @param  array{row: \SineMacula\Laravel\Authorization\Models\Permission, roleCount: int, identityCount: int}  $entry
     * @return array{name: string, guard: string|null, deprecatedAt: string|null, roleCount: int, identityCount: int}
     */
    private function describeEntry(array $entry): array
    {
        return [
            'name'          => $entry['row']->name,
            'guard'         => $entry['row']->guard,
            'deprecatedAt'  => $entry['row']->deprecated_at?->toIso8601String(),
            'roleCount'     => $entry['roleCount'],
            'identityCount' => $entry['identityCount'],
        ];
    }

    /**
     * Render a guard slot for the table output, substituting a
     * human-readable sentinel for the guard-agnostic null.
     *
     * @param  string|null  $guard
     * @return string
     */
    private function renderGuard(?string $guard): string
    {
        return $guard ?? '(any)';
    }

    /**
     * Render a `deprecated_at` timestamp for the table output — ISO
     * 8601 so operators can paste the value straight back into
     * `--before` on the next run.
     *
     * @param  \Carbon\CarbonInterface|null  $timestamp
     * @return string
     */
    private function renderDeprecatedAt(?\Carbon\CarbonInterface $timestamp): string
    {
        return $timestamp?->toIso8601String() ?? '';
    }

    /**
     * Resolve the configured role-permission pivot table name.
     *
     * @return string
     */
    private function rolePermissionsTable(): string
    {
        /** @var string */
        return config('authorization.tables.role_permissions', 'role_permissions');
    }

    /**
     * Resolve the configured identity-permission pivot table name.
     *
     * @return string
     */
    private function authorizablePermissionsTable(): string
    {
        /** @var string */
        return config('authorization.tables.authorizable_permissions', 'authorizable_permissions');
    }
}
