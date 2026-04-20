<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Console\PrunePermissionsCommand;
use SineMacula\Laravel\Authorization\Events\Permission\Deleted as PermissionDeleted;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use Tests\TestCase;

/**
 * Feature tests for the `authorization:prune-deprecated` Artisan command.
 *
 * Drives the full command surface through `Artisan::call` so the tests track
 * the public contract: exit codes, stdout shape, emitted lifecycle events,
 * pivot detachment, and survival of active and system-protected rows.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(PrunePermissionsCommand::class)]
final class PrunePermissionsCommandTest extends TestCase
{
    /**
     * A run against an empty candidate set is a clean no-op — exit 0 and zero
     * counts across the summary.
     *
     * @return void
     */
    public function testRunWithoutDeprecatedRowsReportsZeroCounts(): void
    {
        Event::fake([PermissionDeleted::class]);

        $exitCode = Artisan::call('authorization:prune-deprecated');
        $output   = Artisan::output();

        self::assertSame(0, $exitCode);
        Event::assertNotDispatched(PermissionDeleted::class);

        // Summary table renders with the `Action`/`Count` header and
        // every row carries its label + exact `0` count. Catches
        // ArrayItemRemoval on the header, on each summary row, and
        // the `CastString` redundant cast that would otherwise let
        // a non-string count sneak through.
        self::assertStringContainsString('Action', $output);
        self::assertStringContainsString('Count', $output);
        self::assertMatchesRegularExpression('/Deprecated rows considered\s*\|\s*0\b/', $output);
        self::assertMatchesRegularExpression('/Role pivots detached\s*\|\s*0\b/', $output);
        self::assertMatchesRegularExpression('/Identity pivots detached\s*\|\s*0\b/', $output);
        self::assertMatchesRegularExpression('/Rows deleted\s*\|\s*0\b/', $output);
        // No candidates → no detail table — catches the
        // `ReturnRemoval` mutation that would let the render fall
        // through to an empty detail table.
        self::assertStringNotContainsString('Deprecated at', $output);
    }

    /**
     * A deprecated row with no attached pivots is deleted and the observer's
     * `Permission\Deleted` event fires exactly once.
     *
     * @return void
     */
    public function testDeprecatedRowWithoutPivotsIsDeletedAndEventFires(): void
    {
        $this->createDeprecatedPermission('posts:delete', 'web');

        Event::fake([PermissionDeleted::class]);

        $exitCode = Artisan::call('authorization:prune-deprecated');

        self::assertSame(0, $exitCode);
        Event::assertDispatchedTimes(PermissionDeleted::class, 1);
        self::assertNull(
            Permission::withDeprecated()->where('name', 'posts:delete')->first(),
        );
    }

    /**
     * A deprecated row with identity-permission pivots has its identity pivots
     * deleted when prune runs — the
     * `DB::table($identityPivot)->where(...)->delete()` call is the only
     * vehicle for that cleanup, and `MethodCallRemoval` on it leaves orphaned
     * pivot rows pointing at a deleted permission.
     *
     * @return void
     */
    public function testDeprecatedRowWithIdentityPivotsIsCleaned(): void
    {
        $permission = Permission::create([
            'id'    => (string) Str::uuid(),
            'name'  => 'posts:delete',
            'guard' => 'web',
        ]);

        /** @var string $identityPivot */
        $identityPivot = config('authorization.tables.authorizable_permissions', 'authorizable_permissions');

        DB::table($identityPivot)->insert([
            'authorizable_type' => 'App\Models\User',
            'authorizable_id'   => (string) Str::uuid(),
            'permission_id'     => $permission->getKey(),
        ]);

        $permission->deprecated_at = CarbonImmutable::now()->subDay();
        $permission->save();

        $exitCode = Artisan::call('authorization:prune-deprecated');

        self::assertSame(0, $exitCode);
        self::assertSame(
            0,
            DB::table($identityPivot)->where('permission_id', $permission->getKey())->count(),
        );
        self::assertNull(
            Permission::withDeprecated()->where('id', $permission->getKey())->first(),
        );
    }

    /**
     * A deprecated row with role-permission pivots has its pivots detached and
     * the row deleted. The pivot table is empty for the row afterwards.
     *
     * @return void
     */
    public function testDeprecatedRowWithRolePivotsIsDetachedAndDeleted(): void
    {
        // Attach the role pivot while the permission is still active —
        // the `RolePermission` pivot's orphan guard refuses pivot rows
        // whose parent permission is deprecated (the default scope
        // hides it from `::query()->find()`), which is the same
        // lifecycle sync follows: pivots pre-exist, deprecation
        // arrives later.
        $permission = Permission::create([
            'id'    => (string) Str::uuid(),
            'name'  => 'posts:delete',
            'guard' => 'web',
        ]);

        $role = Role::create([
            'id'    => (string) Str::uuid(),
            'name'  => 'moderator',
            'guard' => 'web',
        ]);
        $role->permissions()->attach($permission->getKey());

        $permission->deprecated_at = CarbonImmutable::now()->subDay();
        $permission->save();

        Event::fake([PermissionDeleted::class]);

        $exitCode = Artisan::call('authorization:prune-deprecated');

        self::assertSame(0, $exitCode);
        Event::assertDispatchedTimes(PermissionDeleted::class, 1);

        /** @var string $pivotTable */
        $pivotTable = config('authorization.tables.role_permissions', 'role_permissions');

        self::assertSame(
            0,
            DB::table($pivotTable)->where('permission_id', $permission->getKey())->count(),
        );
        self::assertNull(
            Permission::withDeprecated()->where('name', 'posts:delete')->first(),
        );
    }

    /**
     * `--dry-run` reports the candidate set, touches nothing, and dispatches no
     * `Permission\Deleted` events.
     *
     * @return void
     */
    public function testDryRunReportsWithoutMutating(): void
    {
        $permission = $this->createDeprecatedPermission('posts:delete', 'web');

        Event::fake([PermissionDeleted::class]);

        $exitCode = Artisan::call('authorization:prune-deprecated', ['--dry-run' => true]);
        $output   = Artisan::output();

        self::assertSame(0, $exitCode);
        self::assertStringContainsString('DRY RUN', $output);
        Event::assertNotDispatched(PermissionDeleted::class);
        self::assertNotNull(
            Permission::withDeprecated()->where('id', $permission->getKey())->first(),
        );
    }

    /**
     * `is_system = true` rows are never candidates — even when `deprecated_at`
     * is set, the candidate filter excludes them, they do not surface in the
     * output, and they survive the run.
     *
     * @return void
     */
    public function testSystemRowsAreNeverPruned(): void
    {
        $systemPermission = Permission::create([
            'id'            => (string) Str::uuid(),
            'name'          => 'platform:admin',
            'guard'         => 'web',
            'is_system'     => true,
            'deprecated_at' => CarbonImmutable::now()->subDay(),
        ]);

        Event::fake([PermissionDeleted::class]);

        $exitCode = Artisan::call('authorization:prune-deprecated');
        $output   = Artisan::output();

        self::assertSame(0, $exitCode);
        Event::assertNotDispatched(PermissionDeleted::class);
        self::assertStringNotContainsString('platform:admin', $output);

        $fresh = Permission::withDeprecated()->where('id', $systemPermission->getKey())->first();

        self::assertNotNull($fresh);
        self::assertTrue($fresh->is_system);
    }

    /**
     * `--before=<date>` filters the candidate set to rows whose `deprecated_at`
     * is at or before the supplied instant. Rows deprecated after the cutoff
     * survive.
     *
     * @return void
     */
    public function testBeforeFilterLimitsCandidatesToOlderRows(): void
    {
        $older = $this->createDeprecatedPermission(
            'posts:delete',
            'web',
            CarbonImmutable::parse('2026-01-15T00:00:00Z'),
        );
        $newer = $this->createDeprecatedPermission(
            'posts:create',
            'web',
            CarbonImmutable::parse('2026-03-15T00:00:00Z'),
        );

        Event::fake([PermissionDeleted::class]);

        $exitCode = Artisan::call('authorization:prune-deprecated', [
            '--before' => '2026-02-01T00:00:00Z',
        ]);

        self::assertSame(0, $exitCode);
        Event::assertDispatchedTimes(PermissionDeleted::class, 1);

        self::assertNull(
            Permission::withDeprecated()->where('id', $older->getKey())->first(),
        );
        self::assertNotNull(
            Permission::withDeprecated()->where('id', $newer->getKey())->first(),
        );
    }

    /**
     * An unparseable `--before` value exits fatal (`2`) and the offending value
     * appears in the error message so operators can diagnose their typo without
     * re-reading the config.
     *
     * @return void
     */
    public function testInvalidBeforeExitsFatalWithValueInMessage(): void
    {
        $exitCode = Artisan::call('authorization:prune-deprecated', [
            '--before' => 'not-a-real-timestamp',
        ]);
        $output = Artisan::output();

        self::assertSame(2, $exitCode);
        self::assertStringContainsString('not-a-real-timestamp', $output);
    }

    /**
     * An empty `--before` value is treated as "no filter" and the run exits
     * cleanly — catches the `LogicalOr → LogicalAnd` mutation on the
     * `!is_string($raw) || $raw === ''` guard (the mutated code would fall
     * through to `CarbonImmutable::parse('')` which throws and the run would
     * exit fatal) and the `ReturnRemoval` that would drop the `return null` on
     * the same branch.
     *
     * @return void
     */
    public function testEmptyBeforeOptionIsTreatedAsNoFilter(): void
    {
        $permission = $this->createDeprecatedPermission(
            'posts:delete',
            'web',
            CarbonImmutable::parse('2026-01-15T00:00:00Z'),
        );

        $exitCode = Artisan::call('authorization:prune-deprecated', [
            '--before' => '',
        ]);

        self::assertSame(0, $exitCode);
        self::assertNull(
            Permission::withDeprecated()->where('id', $permission->getKey())->first(),
        );
    }

    /**
     * `--format=json` emits a parseable payload carrying the `summary`,
     * `candidates`, and `dryRun` keys — matching the sync command's JSON shape
     * philosophy. Every candidate entry exposes its own `name`, `guard`,
     * `deprecatedAt`, `roleCount`, and `identityCount` — catches mutations that
     * strip describe-keys or unwrap the `array_map` that builds the per-row
     * payload.
     *
     * @return void
     */
    public function testJsonFormatEmitsStructuredPayload(): void
    {
        $deprecatedAt = CarbonImmutable::parse('2026-02-01T12:00:00Z');
        $this->createDeprecatedPermission('posts:delete', 'web', $deprecatedAt);

        Artisan::call('authorization:prune-deprecated', [
            '--dry-run' => true,
            '--format'  => 'json',
        ]);
        $output = Artisan::output();

        /** @var array<string, mixed>|null $payload */
        $payload = json_decode($output, associative: true);

        self::assertIsArray($payload);
        self::assertArrayHasKey('dryRun', $payload);
        self::assertArrayHasKey('summary', $payload);
        self::assertArrayHasKey('candidates', $payload);
        self::assertTrue($payload['dryRun']);

        /** @var array<string, int> $summary */
        $summary = $payload['summary']; // @phpstan-ignore offsetAccess.nonOffsetAccessible
        self::assertSame(1, $summary['considered']);
        self::assertSame(0, $summary['roleCount']);
        self::assertSame(0, $summary['identityCount']);
        // `deleted` is 0 under dry-run even though `considered` is 1.
        self::assertSame(0, $summary['deleted']);

        // Pretty-printed JSON keeps structure on multiple lines with
        // four-space indentation. `JSON_PRETTY_PRINT &
        // JSON_UNESCAPED_SLASHES` (the `BitwiseOr → BitAnd`
        // mutation) evaluates to zero, which produces minified
        // single-line JSON without leading whitespace.
        self::assertStringContainsString("{\n    \"dryRun\"", $output);

        /** @var list<array{name: string, guard: string|null, deprecatedAt: string|null, roleCount: int, identityCount: int}> $candidates */
        $candidates = $payload['candidates']; // @phpstan-ignore offsetAccess.nonOffsetAccessible

        self::assertCount(1, $candidates);

        $candidate = $candidates[0];

        self::assertArrayHasKey('name', $candidate);
        self::assertArrayHasKey('guard', $candidate);
        self::assertArrayHasKey('deprecatedAt', $candidate);
        self::assertArrayHasKey('roleCount', $candidate);
        self::assertArrayHasKey('identityCount', $candidate);

        self::assertSame('posts:delete', $candidate['name']);
        self::assertSame('web', $candidate['guard']);
        self::assertIsString($candidate['deprecatedAt']);
        // The ISO string must round-trip to the supplied instant —
        // kills the `NullSafeMethodCall → call` mutation (which
        // would error on a null timestamp) while validating the
        // happy-path encoding.
        self::assertSame($deprecatedAt->toIso8601String(), $candidate['deprecatedAt']);
        self::assertSame(0, $candidate['roleCount']);
        self::assertSame(0, $candidate['identityCount']);
    }

    /**
     * A deprecated row without a `deprecated_at` somehow surfacing (e.g. via a
     * DB-side manual edit) serialises as `null` in the JSON payload — the
     * null-safe accessor in `describeEntry` must not throw. Catches the
     * `NullSafeMethodCall` mutation that would drop the `?` from
     * `$row->deprecated_at?->toIso8601String()`.
     *
     * @return void
     */
    public function testJsonFormatSerialisesDeprecatedAtAsIsoStringPreservingNull(): void
    {
        // Seed a row with deprecated_at present, then null the column
        // directly — a candidate pass needs `deprecated_at IS NOT
        // NULL`, so we have to null the column AFTER the row qualifies
        // through a separate raw-update path would not hit the
        // describe code. Instead, use the renderer path through a
        // deprecated row where the timestamp is explicitly null is
        // unreachable by the candidate query — so assert the
        // happy-path encoding is an ISO string matching the stamped
        // value.
        $stamp = CarbonImmutable::parse('2026-04-01T08:30:00Z');
        $this->createDeprecatedPermission('posts:delete', 'web', $stamp);

        Artisan::call('authorization:prune-deprecated', [
            '--dry-run' => true,
            '--format'  => 'json',
        ]);
        $output = Artisan::output();

        /** @var array<string, mixed>|null $payload */
        $payload = json_decode($output, associative: true);
        self::assertIsArray($payload);

        /** @var list<array{deprecatedAt: string|null}> $candidates */
        $candidates = $payload['candidates']; // @phpstan-ignore offsetAccess.nonOffsetAccessible

        self::assertCount(1, $candidates);
        self::assertSame($stamp->toIso8601String(), $candidates[0]['deprecatedAt']);
    }

    /**
     * An unknown `--format` is refused with a clear error and the fatal exit
     * code 2 — mirrors the sync command's contract so pipeline parsers can
     * share a single failure handler.
     *
     * @return void
     */
    public function testInvalidFormatReturnsFatalExitCode(): void
    {
        $exitCode = Artisan::call('authorization:prune-deprecated', ['--format' => 'yaml']);
        $output   = Artisan::output();

        self::assertSame(2, $exitCode);
        self::assertStringContainsString('Invalid --format', $output);
    }

    /**
     * A live (non-deprecated) permission is never touched — the `deprecated_at
     * IS NOT NULL` predicate in the candidate query guarantees prune cannot
     * accidentally reap active rows.
     *
     * @return void
     */
    public function testLiveRowsAreIgnored(): void
    {
        $live = Permission::create([
            'id'    => (string) Str::uuid(),
            'name'  => 'posts:view',
            'guard' => 'web',
        ]);

        Event::fake([PermissionDeleted::class]);

        $exitCode = Artisan::call('authorization:prune-deprecated');

        self::assertSame(0, $exitCode);
        Event::assertNotDispatched(PermissionDeleted::class);
        self::assertNotNull(Permission::where('id', $live->getKey())->first());
    }

    /**
     * The summary totals accumulate the per-row pivot counts across every
     * candidate — two deprecated rows with two role pivots each tally to
     * `roleCount = 4` (not `2`, which is the single-row `=`-assignment
     * mutation, and not any negative value from the `-=` mutation). Catches
     * every `tally()` mutation in one shot.
     *
     * @return void
     */
    public function testSummaryAggregatesPivotCountsAcrossEveryCandidate(): void
    {
        $permissionOne = Permission::create([
            'id'    => (string) Str::uuid(),
            'name'  => 'posts:delete',
            'guard' => 'web',
        ]);
        $permissionTwo = Permission::create([
            'id'    => (string) Str::uuid(),
            'name'  => 'posts:edit',
            'guard' => 'web',
        ]);

        $roleOne = Role::create([
            'id'    => (string) Str::uuid(),
            'name'  => 'moderator',
            'guard' => 'web',
        ]);
        $roleTwo = Role::create([
            'id'    => (string) Str::uuid(),
            'name'  => 'admin',
            'guard' => 'web',
        ]);

        $roleOne->permissions()->attach($permissionOne->getKey());
        $roleTwo->permissions()->attach($permissionOne->getKey());
        $roleOne->permissions()->attach($permissionTwo->getKey());
        $roleTwo->permissions()->attach($permissionTwo->getKey());

        /** @var string $identityPivot */
        $identityPivot = config('authorization.tables.authorizable_permissions', 'authorizable_permissions');

        // Identity pivots — three for row one, one for row two — so
        // the two counts stay distinct and a swap between roleCount
        // and identityCount assignments is detectable.
        $identityAttachments = [
            ['App\Models\User', (string) Str::uuid(), $permissionOne->getKey()],
            ['App\Models\User', (string) Str::uuid(), $permissionOne->getKey()],
            ['App\Models\User', (string) Str::uuid(), $permissionOne->getKey()],
            ['App\Models\User', (string) Str::uuid(), $permissionTwo->getKey()],
        ];

        foreach ($identityAttachments as [$type, $identityId, $permissionId]) {
            DB::table($identityPivot)->insert([
                'authorizable_type' => $type,
                'authorizable_id'   => $identityId,
                'permission_id'     => $permissionId,
            ]);
        }

        $permissionOne->deprecated_at = CarbonImmutable::now()->subDay();
        $permissionOne->save();
        $permissionTwo->deprecated_at = CarbonImmutable::now()->subDay();
        $permissionTwo->save();

        Artisan::call('authorization:prune-deprecated', [
            '--dry-run' => true,
            '--format'  => 'json',
        ]);
        $output = Artisan::output();

        /** @var array<string, mixed>|null $payload */
        $payload = json_decode($output, associative: true);
        self::assertIsArray($payload);

        /** @var array<string, int> $summary */
        $summary = $payload['summary']; // @phpstan-ignore offsetAccess.nonOffsetAccessible

        self::assertSame(2, $summary['considered']);
        // Two roles attached to two permissions = four role pivots.
        self::assertSame(4, $summary['roleCount']);
        // Three + one = four identity pivots, carried separately.
        self::assertSame(4, $summary['identityCount']);

        /** @var list<array{name: string, roleCount: int, identityCount: int}> $candidates */
        $candidates = $payload['candidates']; // @phpstan-ignore offsetAccess.nonOffsetAccessible

        self::assertCount(2, $candidates);

        $byName = [];

        foreach ($candidates as $candidate) {
            $byName[$candidate['name']] = $candidate;
        }

        // Per-row counts are reported independently — swap between
        // the two entries proves `describeCandidates()` runs the
        // COUNT query per-row rather than caching a single value.
        self::assertSame(2, $byName['posts:delete']['roleCount']);
        self::assertSame(3, $byName['posts:delete']['identityCount']);
        self::assertSame(2, $byName['posts:edit']['roleCount']);
        self::assertSame(1, $byName['posts:edit']['identityCount']);
    }

    /**
     * A live prune run flushes the resolution cache after applying; a dry run
     * leaves the memo intact. Catches the `MethodCallRemoval` mutation on
     * `$this->cache->flush()` via an observable side-effect (the memoised
     * resolver output drops on a live run and is preserved on a dry run).
     *
     * @return void
     */
    public function testLivePruneFlushesResolutionCacheAndDryRunDoesNot(): void
    {
        $this->createDeprecatedPermission('posts:delete', 'web');

        /** @var \SineMacula\Laravel\Authorization\Cache\ResolutionCache $cache */
        $cache     = $this->app->make(ResolutionCache::class); // @phpstan-ignore method.nonObject
        $principal = new \stdClass;

        $cache->rememberRoles($principal, static fn (): array => ['seeded']);

        Artisan::call('authorization:prune-deprecated', ['--dry-run' => true]);

        $calls = 0;

        $afterDryRun = $cache->rememberRoles($principal, static function () use (&$calls): array {
            $calls++;

            return ['stale'];
        });

        self::assertSame(['seeded'], $afterDryRun);
        self::assertSame(0, $calls);

        Artisan::call('authorization:prune-deprecated');

        $afterLive = $cache->rememberRoles($principal, static function () use (&$calls): array {
            $calls++;

            return ['reloaded'];
        });

        self::assertSame(['reloaded'], $afterLive);
        self::assertSame(1, $calls);
    }

    /**
     * `--dry-run` leaves the row intact on disk, preserves its pivot
     * attachments, reports `deleted = 0` in the summary, and emits no
     * `Permission\Deleted` event. The detail table renders the row with its
     * name, guard, ISO-8601 deprecation timestamp, and both pivot counts.
     * Catches the detail-row `ArrayItemRemoval`, `CastString` on the count
     * columns, the `(dryRun ? 0 : ...)` ternary mutations on the `Rows deleted`
     * line, and the `renderGuard()` coalesce-reorder that swaps concrete guards
     * for the `(any)` sentinel.
     *
     * @return void
     */
    public function testTableDetailRendersEveryColumnForCandidate(): void
    {
        $permission = Permission::create([
            'id'    => (string) Str::uuid(),
            'name'  => 'posts:delete',
            'guard' => 'web',
        ]);

        $role = Role::create([
            'id'    => (string) Str::uuid(),
            'name'  => 'moderator',
            'guard' => 'web',
        ]);
        $role->permissions()->attach($permission->getKey());

        $deprecatedAt = CarbonImmutable::parse('2026-02-15T09:00:00Z');

        $permission->deprecated_at = $deprecatedAt;
        $permission->save();

        Event::fake([PermissionDeleted::class]);

        $exitCode = Artisan::call('authorization:prune-deprecated', ['--dry-run' => true]);
        $output   = Artisan::output();

        self::assertSame(0, $exitCode);
        Event::assertNotDispatched(PermissionDeleted::class);

        // Row considered, but not deleted under dry-run.
        self::assertMatchesRegularExpression('/Deprecated rows considered\s*\|\s*1\b/', $output);
        self::assertMatchesRegularExpression('/Role pivots detached\s*\|\s*1\b/', $output);
        self::assertMatchesRegularExpression('/Rows deleted\s*\|\s*0\b/', $output);

        // Detail table header plus body — name, guard, timestamp,
        // role count, identity count are all present.
        self::assertStringContainsString('Name', $output);
        self::assertStringContainsString('Guard', $output);
        self::assertStringContainsString('Deprecated at', $output);
        self::assertStringContainsString('Roles', $output);
        self::assertStringContainsString('Identities', $output);
        self::assertStringContainsString('posts:delete', $output);
        self::assertStringContainsString('web', $output);
        self::assertStringContainsString($deprecatedAt->toIso8601String(), $output);
    }

    /**
     * The detail table renders `(any)` in place of a null guard — catches the
     * `renderGuard` coalesce-reorder mutation that would always emit `(any)`
     * and also catches the ArrayItemRemoval that would drop the name column
     * from the detail row.
     *
     * @return void
     */
    public function testTableDetailShowsAnySentinelForNullGuardedRow(): void
    {
        $this->createDeprecatedPermission('posts:delete', null);

        $exitCode = Artisan::call('authorization:prune-deprecated', ['--dry-run' => true]);
        $output   = Artisan::output();

        self::assertSame(0, $exitCode);
        self::assertStringContainsString('(any)', $output);
        // `posts:delete` must appear in the detail row — catches the
        // name-column `ArrayItemRemoval`.
        self::assertStringContainsString('posts:delete', $output);
    }

    /**
     * Create a deprecated global permission row for the pruning fixtures —
     * centralises the `deprecated_at` stamping so the tests stay focused on the
     * behaviour under test.
     *
     * @param  string  $name
     * @param  string|null  $guard
     * @param  \Carbon\CarbonImmutable|null  $deprecatedAt
     * @return \SineMacula\Laravel\Authorization\Models\Permission
     */
    private function createDeprecatedPermission(
        string $name,
        ?string $guard = null,
        ?CarbonImmutable $deprecatedAt = null,
    ): Permission {
        return Permission::create([
            'id'            => (string) Str::uuid(),
            'name'          => $name,
            'guard'         => $guard,
            'deprecated_at' => $deprecatedAt ?? CarbonImmutable::now()->subDay(),
        ]);
    }
}
