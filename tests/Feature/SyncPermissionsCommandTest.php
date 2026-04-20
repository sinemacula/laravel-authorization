<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Cache\ResolutionCache;
use SineMacula\Laravel\Authorization\Console\Support\PermissionDiff;
use SineMacula\Laravel\Authorization\Console\Support\PermissionDiffBuilder;
use SineMacula\Laravel\Authorization\Console\Support\PermissionEnumWalker;
use SineMacula\Laravel\Authorization\Console\Support\PermissionTuple;
use SineMacula\Laravel\Authorization\Console\SyncPermissionsCommand;
use SineMacula\Laravel\Authorization\Events\Permission\Created as PermissionCreated;
use SineMacula\Laravel\Authorization\Events\Permission\Deleted as PermissionDeleted;
use SineMacula\Laravel\Authorization\Events\Permission\Deprecated as PermissionDeprecated;
use SineMacula\Laravel\Authorization\Events\Permission\Reinstated as PermissionReinstated;
use SineMacula\Laravel\Authorization\Events\Permission\Updated as PermissionUpdated;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use Tests\Feature\Stubs\SyncStubEmptyGuardsPermission;
use Tests\Feature\Stubs\SyncStubExtendedPermission;
use Tests\Feature\Stubs\SyncStubPermission;
use Tests\Feature\Stubs\SyncStubReducedPermission;
use Tests\Feature\Stubs\SyncStubSecondaryPermission;
use Tests\Feature\Stubs\SyncStubUpdatedMetadataPermission;
use Tests\TestCase;

/**
 * Feature tests for the `authorization:sync` Artisan command.
 *
 * Drives the full command surface through `Artisan::call` so the
 * tests track the public contract a consumer would observe: exit
 * codes, stdout shape, emitted events, and the resulting permission
 * rows.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 * @SuppressWarnings("php:S1448")
 */
#[CoversClass(SyncPermissionsCommand::class)]
#[CoversClass(PermissionDiff::class)]
#[CoversClass(PermissionDiffBuilder::class)]
#[CoversClass(PermissionEnumWalker::class)]
#[CoversClass(PermissionTuple::class)]
#[CoversClass(PermissionDeprecated::class)]
#[CoversClass(PermissionReinstated::class)]
final class SyncPermissionsCommandTest extends TestCase
{
    /**
     * A fresh sync against an empty DB inserts one row per
     * `(name, guard)` tuple and emits one `Permission\Created`
     * event per insert.
     *
     * @return void
     */
    public function testFreshSyncInsertsRowsForEveryTuple(): void
    {
        $this->configureEnums([SyncStubPermission::class]);

        Event::fake([PermissionCreated::class]);

        $exitCode = Artisan::call('authorization:sync');
        $output   = Artisan::output();

        self::assertSame(0, $exitCode);
        // POSTS_VIEW expands into two rows (web, api), POSTS_DELETE
        // contributes one guard-agnostic row — three `Created`
        // events total.
        Event::assertDispatchedTimes(PermissionCreated::class, 3);

        /** @var \Illuminate\Database\Eloquent\Collection<int, \SineMacula\Laravel\Authorization\Models\Permission> $rows */
        // @phpstan-ignore staticMethod.dynamicCall, staticMethod.dynamicCall
        $rows = Permission::withDeprecated()->orderBy('name')->orderBy('guard')->get();

        self::assertCount(3, $rows);
        $first  = $rows->get(0);
        $second = $rows->get(1);
        $third  = $rows->get(2);
        self::assertInstanceOf(Permission::class, $first);
        self::assertInstanceOf(Permission::class, $second);
        self::assertInstanceOf(Permission::class, $third);
        self::assertSame('posts:delete', $first->name);
        self::assertNull($first->guard);
        self::assertSame('posts:view', $second->name);
        self::assertSame('api', $second->guard);
        self::assertSame('posts:view', $third->name);
        self::assertSame('web', $third->guard);
        self::assertSame('View posts', $second->description);
        self::assertSame('Content', $second->category);

        // Summary table carries the bucket/count header plus one row
        // per bucket. The `Added` label must appear (ArrayItemRemoval
        // guards), the exact count `3` must appear next to it
        // (CastString guards), and the zero-count buckets must still
        // render their labels so the operator sees the full picture.
        self::assertStringContainsString('Bucket', $output);
        self::assertStringContainsString('Count', $output);
        self::assertStringContainsString('Added', $output);
        self::assertMatchesRegularExpression('/Added\s*\|\s*3\b/', $output);
        self::assertStringContainsString('Updated', $output);
        self::assertStringContainsString('Reinstated', $output);
        self::assertStringContainsString('Retired', $output);
        self::assertStringContainsString('Protected', $output);
        self::assertStringContainsString('Unchanged', $output);
        self::assertStringContainsString('Role references on retired', $output);

        // Detail table header and body row contents — the `Name`,
        // `Guard`, and `Action` columns are present, and each
        // enum-derived tuple is listed. Guard-null renders as the
        // `(any)` sentinel; concrete guards pass through verbatim.
        self::assertStringContainsString('Name', $output);
        self::assertStringContainsString('Guard', $output);
        self::assertStringContainsString('Action', $output);
        self::assertStringContainsString('posts:view', $output);
        self::assertStringContainsString('posts:delete', $output);
        self::assertStringContainsString('web', $output);
        self::assertStringContainsString('api', $output);
        self::assertStringContainsString('(any)', $output);
        self::assertStringContainsString('add', $output);
    }

    /**
     * Re-running sync against the same enum state is idempotent —
     * zero writes, zero events, all tuples report as `unchanged`.
     *
     * @return void
     */
    public function testIdempotentRerunProducesNoWritesOrEvents(): void
    {
        $this->configureEnums([SyncStubPermission::class]);

        Artisan::call('authorization:sync');

        /** @var string $table */
        $table    = config('authorization.tables.permissions', 'permissions');
        $snapshot = \Illuminate\Support\Facades\DB::table($table)
            ->orderBy('name')
            ->orderBy('guard')
            ->pluck('updated_at', 'name')
            ->all();

        Event::fake([
            PermissionCreated::class,
            PermissionUpdated::class,
            PermissionDeleted::class,
            PermissionDeprecated::class,
            PermissionReinstated::class,
        ]);

        $exitCode = Artisan::call('authorization:sync');

        self::assertSame(0, $exitCode);
        Event::assertNotDispatched(PermissionCreated::class);
        Event::assertNotDispatched(PermissionUpdated::class);
        Event::assertNotDispatched(PermissionDeleted::class);
        Event::assertNotDispatched(PermissionDeprecated::class);
        Event::assertNotDispatched(PermissionReinstated::class);

        $after = \Illuminate\Support\Facades\DB::table($table)
            ->orderBy('name')
            ->orderBy('guard')
            ->pluck('updated_at', 'name')
            ->all();

        self::assertSame($snapshot, $after);
        self::assertStringContainsString('Unchanged', Artisan::output());
    }

    /**
     * Adding a case between sync passes inserts exactly one row
     * and emits exactly one `Permission\Created`.
     *
     * @return void
     */
    public function testAddingNewCaseInsertsOneRow(): void
    {
        $this->configureEnums([SyncStubPermission::class]);
        Artisan::call('authorization:sync');

        $this->configureEnums([SyncStubExtendedPermission::class]);

        Event::fake([PermissionCreated::class]);

        $exitCode = Artisan::call('authorization:sync');

        self::assertSame(0, $exitCode);
        Event::assertDispatchedTimes(PermissionCreated::class, 1);
        Event::assertDispatched(
            PermissionCreated::class,
            static fn (PermissionCreated $event): bool => $event->permission->name === 'posts:create'
                && $event->permission->guard                                       === 'web',
        );

        self::assertNotNull(
            Permission::query()->where('name', 'posts:create')->where('guard', 'web')->first(),
        );
    }

    /**
     * Removing a case between sync passes soft-retires the row —
     * `deprecated_at` is stamped, the row survives, and exactly
     * one `Permission\Deprecated` event fires (no `Deleted`).
     *
     * @return void
     */
    public function testRemovingCaseSoftRetiresRow(): void
    {
        $this->configureEnums([SyncStubPermission::class]);
        Artisan::call('authorization:sync');

        $this->configureEnums([SyncStubReducedPermission::class]);

        Event::fake([PermissionDeprecated::class, PermissionDeleted::class]);

        $exitCode = Artisan::call('authorization:sync');
        $output   = Artisan::output();

        self::assertSame(0, $exitCode);
        Event::assertDispatchedTimes(PermissionDeprecated::class, 1);
        Event::assertNotDispatched(PermissionDeleted::class);

        $retired = Permission::withDeprecated()->where('name', 'posts:delete')->first();

        self::assertNotNull($retired);
        self::assertNotNull($retired->deprecated_at);

        // Summary reports one retire, detail table lists the row by
        // name with the `retire` action — catches the detail-loop
        // retire-branch `Foreach_ → []` and `ArrayItemRemoval`
        // mutations.
        self::assertMatchesRegularExpression('/Retired\s*\|\s*1\b/', $output);
        self::assertStringContainsString('posts:delete', $output);
        self::assertStringContainsString('retire', $output);
    }

    /**
     * Re-adding a previously retired case clears `deprecated_at`
     * and emits a single `Permission\Reinstated` event.
     *
     * @return void
     */
    public function testReinstatingRetiredCaseClearsDeprecatedTimestamp(): void
    {
        $this->configureEnums([SyncStubPermission::class]);
        Artisan::call('authorization:sync');

        $this->configureEnums([SyncStubReducedPermission::class]);
        Artisan::call('authorization:sync');

        // Prove the row is deprecated before the reinstate run.
        $retired = Permission::withDeprecated()->where('name', 'posts:delete')->first();
        self::assertNotNull($retired);
        self::assertNotNull($retired->deprecated_at);

        $this->configureEnums([SyncStubPermission::class]);

        Event::fake([PermissionReinstated::class]);

        $exitCode = Artisan::call('authorization:sync');
        $output   = Artisan::output();

        self::assertSame(0, $exitCode);
        Event::assertDispatchedTimes(PermissionReinstated::class, 1);
        Event::assertDispatched(
            PermissionReinstated::class,
            static fn (PermissionReinstated $event): bool => $event->permission->name === 'posts:delete',
        );

        $fresh = Permission::where('name', 'posts:delete')->first();

        self::assertNotNull($fresh);
        self::assertNull($fresh->deprecated_at);

        // Summary reports one reinstate, detail table carries the
        // row by name with the `reinstate` action — catches the
        // reinstate-branch `Foreach_ → []` and `ArrayItemRemoval`
        // mutations in `collectDetailRows`.
        self::assertMatchesRegularExpression('/Reinstated\s*\|\s*1\b/', $output);
        self::assertStringContainsString('posts:delete', $output);
        self::assertStringContainsString('reinstate', $output);
    }

    /**
     * Metadata drift (description / category changes) refreshes the
     * row and emits exactly one `Permission\Updated` per drifted
     * row.
     *
     * @return void
     */
    public function testMetadataDriftUpdatesMatchingRows(): void
    {
        $this->configureEnums([SyncStubPermission::class]);
        Artisan::call('authorization:sync');

        $this->configureEnums([SyncStubUpdatedMetadataPermission::class]);

        Event::fake([PermissionUpdated::class]);

        $exitCode = Artisan::call('authorization:sync');
        $output   = Artisan::output();

        self::assertSame(0, $exitCode);
        // Both `posts:view` rows (web + api) pick up the new
        // metadata; `posts:delete` is unchanged.
        Event::assertDispatchedTimes(PermissionUpdated::class, 2);

        /** @var \Illuminate\Database\Eloquent\Collection<int, \SineMacula\Laravel\Authorization\Models\Permission> $refreshed */
        // @phpstan-ignore staticMethod.dynamicCall
        $refreshed = Permission::where('name', 'posts:view')->orderBy('guard')->get();

        foreach ($refreshed as $row) {
            self::assertSame('View published posts', $row->description);
            self::assertSame('Publishing', $row->category);
        }

        // Summary table reports two updates (CastString + exact
        // count), detail table lists both `posts:view` rows with the
        // `update` action and their guards — catches the detail-row
        // `ArrayItemRemoval`/`Foreach_` mutations on the update
        // branch of `collectDetailRows`.
        self::assertMatchesRegularExpression('/Updated\s*\|\s*2\b/', $output);
        self::assertStringContainsString('posts:view', $output);
        self::assertStringContainsString('update', $output);
        self::assertStringContainsString('web', $output);
        self::assertStringContainsString('api', $output);
    }

    /**
     * System-flagged rows with no matching tuple surface in the
     * `protected` bucket and are left untouched. No lifecycle events
     * fire for them.
     *
     * @return void
     */
    public function testSystemPermissionsAreReportedAsProtected(): void
    {
        $this->configureEnums([SyncStubPermission::class]);

        $protected = Permission::create([
            'id'        => (string) Str::uuid(),
            'name'      => 'platform:admin',
            'guard'     => 'web',
            'is_system' => true,
        ]);

        Event::fake([
            PermissionUpdated::class,
            PermissionDeleted::class,
            PermissionDeprecated::class,
        ]);

        $exitCode = Artisan::call('authorization:sync');
        $output   = Artisan::output();

        self::assertSame(0, $exitCode);
        self::assertStringContainsString('Protected', $output);

        // Detail table lists the protected row by name, guard, and
        // action — catches the `collectDetailRows` protected-loop
        // `Foreach_ → []` and `ArrayItemRemoval` mutations.
        self::assertMatchesRegularExpression('/Protected\s*\|\s*1\b/', $output);
        self::assertStringContainsString('platform:admin', $output);
        self::assertStringContainsString('protected', $output);

        Event::assertNotDispatched(
            PermissionUpdated::class,
            static fn (PermissionUpdated $event) => $event->permission->is($protected),
        );
        Event::assertNotDispatched(PermissionDeleted::class);
        Event::assertNotDispatched(PermissionDeprecated::class);

        /** @var \SineMacula\Laravel\Authorization\Models\Permission|null $fresh */
        $fresh = Permission::withDeprecated()->where('id', $protected->getKey())->first();

        self::assertInstanceOf(Permission::class, $fresh);
        self::assertTrue($fresh->is_system);
        self::assertNull($fresh->deprecated_at);
    }

    /**
     * `--force-delete` hard-deletes retired rows and emits
     * `Permission\Deleted` instead of `Permission\Deprecated`. A
     * subsequent run reports nothing.
     *
     * @return void
     */
    public function testForceDeleteHardDeletesRetiredRowsAndSubsequentRunIsClean(): void
    {
        $this->configureEnums([SyncStubPermission::class]);
        Artisan::call('authorization:sync');

        $this->configureEnums([SyncStubReducedPermission::class]);

        Event::fake([PermissionDeleted::class, PermissionDeprecated::class]);

        $exitCode = Artisan::call('authorization:sync', ['--force-delete' => true]);

        self::assertSame(0, $exitCode);
        Event::assertDispatchedTimes(PermissionDeleted::class, 1);
        Event::assertNotDispatched(PermissionDeprecated::class);

        self::assertNull(
            Permission::withDeprecated()->where('name', 'posts:delete')->first(),
        );

        Event::fake([PermissionDeleted::class, PermissionCreated::class]);

        $secondExit = Artisan::call('authorization:sync', ['--force-delete' => true]);

        self::assertSame(0, $secondExit);
        Event::assertNotDispatched(PermissionDeleted::class);
        Event::assertNotDispatched(PermissionCreated::class);
    }

    /**
     * `--dry-run` with drift reports the diff, exits 1, writes
     * nothing, and dispatches no lifecycle events.
     *
     * @return void
     */
    public function testDryRunWithDriftExitsOneWithoutWriting(): void
    {
        $this->configureEnums([SyncStubPermission::class]);

        Event::fake([
            PermissionCreated::class,
            PermissionUpdated::class,
            PermissionDeleted::class,
            PermissionDeprecated::class,
            PermissionReinstated::class,
        ]);

        $exitCode = Artisan::call('authorization:sync', ['--dry-run' => true]);

        self::assertSame(1, $exitCode);
        self::assertStringContainsString('DRY RUN', Artisan::output());
        Event::assertNotDispatched(PermissionCreated::class);
        Event::assertNotDispatched(PermissionUpdated::class);
        Event::assertNotDispatched(PermissionDeleted::class);
        Event::assertNotDispatched(PermissionDeprecated::class);
        Event::assertNotDispatched(PermissionReinstated::class);

        self::assertSame(0, Permission::withDeprecated()->count()); // @phpstan-ignore staticMethod.dynamicCall
    }

    /**
     * `--dry-run` against an already-synced state reports no drift
     * and exits 0.
     *
     * @return void
     */
    public function testDryRunWithNoDriftExitsZero(): void
    {
        $this->configureEnums([SyncStubPermission::class]);
        Artisan::call('authorization:sync');

        Event::fake([
            PermissionCreated::class,
            PermissionUpdated::class,
            PermissionDeleted::class,
            PermissionDeprecated::class,
            PermissionReinstated::class,
        ]);

        $exitCode = Artisan::call('authorization:sync', ['--dry-run' => true]);

        self::assertSame(0, $exitCode);
        Event::assertNotDispatched(PermissionCreated::class);
        Event::assertNotDispatched(PermissionUpdated::class);
        Event::assertNotDispatched(PermissionDeleted::class);
        Event::assertNotDispatched(PermissionDeprecated::class);
        Event::assertNotDispatched(PermissionReinstated::class);
    }

    /**
     * `--format=json` emits parseable JSON carrying the
     * `summary`, `changes`, and `dryRun` keys. The `changes.add`
     * bucket is populated with one describe-tuple object per enum
     * tuple carrying the exact `name`, `guard`, and `action` keys —
     * catches mutations that strip describe fields or unwrap the
     * `array_map` wrapper.
     *
     * @return void
     */
    public function testJsonFormatEmitsStructuredPayload(): void
    {
        $this->configureEnums([SyncStubPermission::class]);

        Artisan::call('authorization:sync', [
            '--dry-run' => true,
            '--format'  => 'json',
        ]);
        $output = Artisan::output();

        /** @var array<string, mixed>|null $payload */
        $payload = \json_decode($output, associative: true);

        self::assertIsArray($payload);
        self::assertArrayHasKey('dryRun', $payload);
        self::assertArrayHasKey('summary', $payload);
        self::assertArrayHasKey('changes', $payload);
        self::assertTrue($payload['dryRun']);

        /** @var array<string, int> $summary */
        $summary = $payload['summary'];
        self::assertSame(3, $summary['add']);
        self::assertSame(0, $summary['update']);
        self::assertSame(0, $summary['reinstate']);
        self::assertSame(0, $summary['retire']);
        self::assertSame(0, $summary['protected']);
        self::assertSame(0, $summary['unchanged']);
        self::assertSame(0, $summary['roleReferences']);

        // Pretty-printed JSON keeps structure on multiple lines with
        // four-space indentation. `JSON_PRETTY_PRINT &
        // JSON_UNESCAPED_SLASHES` (the `BitwiseOr → BitAnd`
        // mutation) evaluates to zero, which produces minified
        // single-line JSON without leading whitespace.
        self::assertStringContainsString("{\n    \"dryRun\"", $output);

        /** @var array<string, mixed> $changes */
        $changes = $payload['changes']; // @phpstan-ignore offsetAccess.nonOffsetAccessible

        /** @var list<array{name: string, guard: string|null, action: string}> $add */
        $add = $changes['add']; // @phpstan-ignore offsetAccess.nonOffsetAccessible
        self::assertCount(3, $add);

        // Every entry must carry name, guard and action — exactly,
        // with action equal to the bucket key. Keyed look-up by name
        // keeps the assertion robust to sort order.
        $byName = [];

        foreach ($add as $entry) {
            self::assertArrayHasKey('name', $entry);
            self::assertArrayHasKey('guard', $entry);
            self::assertArrayHasKey('action', $entry);
            self::assertSame('add', $entry['action']);
            $byName[$entry['name'] . '|' . ($entry['guard'] ?? '')] = $entry;
        }

        self::assertArrayHasKey('posts:delete|', $byName);
        self::assertNull($byName['posts:delete|']['guard']);
        self::assertArrayHasKey('posts:view|web', $byName);
        self::assertSame('web', $byName['posts:view|web']['guard']);
        self::assertArrayHasKey('posts:view|api', $byName);
        self::assertSame('api', $byName['posts:view|api']['guard']);
    }

    /**
     * An unknown `--format` is refused with a clear error and the
     * fatal exit code 2.
     *
     * @return void
     */
    public function testInvalidFormatReturnsFatalExitCode(): void
    {
        $this->configureEnums([SyncStubPermission::class]);

        $exitCode = Artisan::call('authorization:sync', ['--format' => 'yaml']);

        self::assertSame(2, $exitCode);
        self::assertStringContainsString('Invalid --format', Artisan::output());
    }

    /**
     * An empty `permission_enums` config is a clean no-op — exit 0
     * and no rows created.
     *
     * @return void
     */
    public function testEmptyPermissionEnumsConfigIsCleanNoop(): void
    {
        $this->configureEnums([]);

        Event::fake([PermissionCreated::class]);

        $exitCode = Artisan::call('authorization:sync');

        self::assertSame(0, $exitCode);
        Event::assertNotDispatched(PermissionCreated::class);
        self::assertSame(0, Permission::withDeprecated()->count()); // @phpstan-ignore staticMethod.dynamicCall
    }

    /**
     * An invalid `#[Permission]` attribute — explicit empty
     * `guards: []` — surfaces as the fatal exit code 2 with a
     * message naming the enum class and case.
     *
     * @return void
     */
    public function testInvalidAttributeExitsFatalWithDescriptiveMessage(): void
    {
        $this->configureEnums([SyncStubEmptyGuardsPermission::class]);

        $exitCode = Artisan::call('authorization:sync');
        $output   = Artisan::output();

        self::assertSame(2, $exitCode);
        self::assertStringContainsString(SyncStubEmptyGuardsPermission::class, $output);
        self::assertStringContainsString('POSTS_BROKEN', $output);
    }

    /**
     * A retire bucket carrying a role-permission pivot reports the
     * pivot count in the summary and leaves the pivot intact — the
     * prune command's job, not sync's.
     *
     * @return void
     */
    public function testRetiredRowsWithRoleReferencesReportCountAndKeepPivots(): void
    {
        $this->configureEnums([SyncStubPermission::class]);
        Artisan::call('authorization:sync');

        /** @var \SineMacula\Laravel\Authorization\Models\Permission $delete */
        $delete = Permission::where('name', 'posts:delete')->firstOrFail();

        $role = Role::create([
            'id'    => (string) Str::uuid(),
            'name'  => 'moderator',
            'guard' => 'web',
        ]);
        $role->permissions()->attach($delete->getKey());

        $this->configureEnums([SyncStubReducedPermission::class]);

        $exitCode = Artisan::call('authorization:sync', ['--format' => 'json']);
        $output   = Artisan::output();

        self::assertSame(0, $exitCode);

        /** @var array<string, mixed>|null $payload */
        $payload = \json_decode($output, associative: true);
        self::assertIsArray($payload);

        /** @var array<string, int> $summary */
        $summary = $payload['summary']; // @phpstan-ignore offsetAccess.nonOffsetAccessible

        // Exactly one pivot reference must be reported. Catches the
        // `countRoleReferences` mutations that:
        //   - skip the tuple-key loop (reports every non-system row
        //     as a candidate),
        //   - skip the row loop (reports 0),
        //   - short-circuit on an empty candidate list (reports 0).
        self::assertSame(1, $summary['roleReferences']);
        self::assertSame(1, $summary['retire']);

        // The per-row pivot count must still be one — sync never
        // detaches.
        /** @var string $pivotTable */
        $pivotTable = config('authorization.tables.role_permissions', 'role_permissions');

        self::assertSame(
            1,
            \Illuminate\Support\Facades\DB::table($pivotTable)
                ->where('permission_id', $delete->getKey())
                ->count(),
        );
    }

    /**
     * The internal `compositeKey` helper must distinguish rows
     * whose `name` differs only at the `(name, guard)` boundary
     * from tuples that would collide under naïve string
     * concatenation. A row named `posts:view-web` with guard null
     * must NOT match a tuple with name `posts:view` and guard `web`
     * for candidate-filter purposes: removing the row from the enum
     * and attaching a role pivot to it must surface the pivot on
     * the `roleReferences` count even when the tuple key has the
     * same concatenated characters.
     *
     * @return void
     */
    public function testCompositeKeyInRoleReferenceCountDoesNotCollideAcrossBoundary(): void
    {
        // Seed the enum with a canonical row and attach a role pivot
        // to a separate row whose name would concatenate to the same
        // naked string as the tuple but compose to a distinct match
        // key under the real null-byte separator.
        $this->configureEnums([SyncStubPermission::class]);
        Artisan::call('authorization:sync');

        // `posts:view` with guard `web` is in the enum. The DB row
        // below uses `posts:view-web` with null guard — both would
        // concatenate to `posts:view-web` without the null-byte
        // separator and would therefore wrongly match the tuple key
        // `posts:view` + null-byte + `web`.
        $lookalike = Permission::create([
            'id'    => (string) Str::uuid(),
            'name'  => 'posts:viewweb',
            'guard' => null,
        ]);

        $role = Role::create([
            'id'    => (string) Str::uuid(),
            'name'  => 'moderator',
            'guard' => 'web',
        ]);
        $role->permissions()->attach($lookalike->getKey());

        // Dry-run against the same enum — the lookalike must surface
        // as a retire candidate and its role pivot must be counted.
        Artisan::call('authorization:sync', [
            '--dry-run' => true,
            '--format'  => 'json',
        ]);
        $output = Artisan::output();

        /** @var array<string, mixed>|null $payload */
        $payload = \json_decode($output, associative: true);
        self::assertIsArray($payload);

        /** @var array<string, int> $summary */
        $summary = $payload['summary']; // @phpstan-ignore offsetAccess.nonOffsetAccessible

        self::assertSame(1, $summary['retire']);
        self::assertSame(1, $summary['roleReferences']);
        self::assertSame(3, $summary['unchanged']);
    }

    /**
     * `countRoleReferences` must skip matched rows and system rows
     * even when they are interleaved with non-system retire
     * candidates. Breaking the `continue` into a `break` would drop
     * every candidate that appears after the first matched or system
     * row; empty-loop mutants would drop every candidate outright.
     *
     * @return void
     */
    public function testRoleReferenceCountIgnoresMatchedAndSystemRowsAroundRetireCandidate(): void
    {
        // System orphan seeded BEFORE the enum sync so it lands
        // ahead of the retire candidate in the `loadCurrentRows()`
        // insertion-order iteration — if the system-row branch
        // replaced its `continue` with `break`, it would abort the
        // scan before reaching the retire candidate and drop the
        // pivot count to zero.
        Permission::create([
            'id'        => (string) Str::uuid(),
            'name'      => 'platform:admin',
            'guard'     => 'web',
            'is_system' => true,
        ]);

        $this->configureEnums([SyncStubPermission::class]);
        Artisan::call('authorization:sync');

        /** @var \SineMacula\Laravel\Authorization\Models\Permission $delete */
        $delete = Permission::where('name', 'posts:delete')->firstOrFail();

        $role = Role::create([
            'id'    => (string) Str::uuid(),
            'name'  => 'moderator',
            'guard' => 'web',
        ]);
        // Only the retire candidate (posts:delete) has a pivot — the
        // matched posts:view rows and the system row must NOT
        // contribute to the count.
        $role->permissions()->attach($delete->getKey());

        /** @var \SineMacula\Laravel\Authorization\Models\Permission $viewWeb */
        $viewWeb = Permission::where('name', 'posts:view')->where('guard', 'web')->firstOrFail();
        $role->permissions()->attach($viewWeb->getKey());

        // Drop posts:delete from the enum so it lands in retire.
        $this->configureEnums([SyncStubReducedPermission::class]);

        Artisan::call('authorization:sync', [
            '--dry-run' => true,
            '--format'  => 'json',
        ]);
        $output = Artisan::output();

        /** @var array<string, mixed>|null $payload */
        $payload = \json_decode($output, associative: true);
        self::assertIsArray($payload);

        /** @var array<string, int> $summary */
        $summary = $payload['summary']; // @phpstan-ignore offsetAccess.nonOffsetAccessible

        // Only the retire candidate's pivot is counted — matched
        // (posts:view) and system (platform:admin) are filtered even
        // though posts:view also has a pivot attached.
        self::assertSame(1, $summary['roleReferences']);
        self::assertSame(1, $summary['retire']);
        self::assertSame(1, $summary['protected']);
        self::assertSame(2, $summary['unchanged']);
    }

    /**
     * `--dry-run` drift detection sums every mutating bucket. A run
     * with retire-only drift must still exit `EXIT_DRIFT`; a run
     * with reinstate-only drift must also exit `EXIT_DRIFT`; a run
     * with only `protected` and `unchanged` populated must exit
     * zero. An update-only drift and an add-only drift are also
     * covered so every summand in `count(add) + count(update) +
     * count(reinstate) + count(retire)` contributes to a passing
     * test — catches the `Plus → Minus` mutations one arm at a time.
     *
     * @return void
     */
    public function testDryRunDriftDetectionSumsEveryMutatingBucket(): void
    {
        // Add-only drift: empty DB, non-empty enum.
        $this->configureEnums([SyncStubPermission::class]);

        $addOnly = Artisan::call('authorization:sync', ['--dry-run' => true]);
        self::assertSame(1, $addOnly);

        // Apply live so the DB catches up, then update-only drift
        // via metadata drift on the same enum shape.
        Artisan::call('authorization:sync');
        $this->configureEnums([SyncStubUpdatedMetadataPermission::class]);

        $updateOnly = Artisan::call('authorization:sync', ['--dry-run' => true]);
        self::assertSame(1, $updateOnly);

        // Apply the metadata drift, switch back to the base enum
        // (unchanged shape against the newly-persisted metadata would
        // still drift back). Align the DB against the base enum
        // first so the retire-only scenario has clean metadata.
        Artisan::call('authorization:sync');
        $this->configureEnums([SyncStubPermission::class]);
        Artisan::call('authorization:sync');

        // Retire-only drift — no metadata drift, no adds, only the
        // `posts:delete` row lands in `retire`. Catches the
        // `reinstate - retire` sign flip: a single-retire scenario
        // computes driftCount = -1 under mutation, returning SUCCESS
        // instead of EXIT_DRIFT.
        $this->configureEnums([SyncStubReducedPermission::class]);

        $retireOnly = Artisan::call('authorization:sync', ['--dry-run' => true]);
        self::assertSame(1, $retireOnly);

        // Apply the retire live, then reinstate-only by restoring
        // the full enum — `reinstate=1`, no retire/add/update.
        Artisan::call('authorization:sync');
        $this->configureEnums([SyncStubPermission::class]);

        $reinstateOnly = Artisan::call('authorization:sync', ['--dry-run' => true]);
        self::assertSame(1, $reinstateOnly);

        // Apply the reinstate live, add a system-flagged orphan,
        // and leave the enum alone — zero mutating buckets remain.
        Artisan::call('authorization:sync');
        Permission::create([
            'id'        => (string) Str::uuid(),
            'name'      => 'platform:admin',
            'guard'     => 'web',
            'is_system' => true,
        ]);

        $protectedAndUnchangedOnly = Artisan::call('authorization:sync', ['--dry-run' => true]);
        self::assertSame(0, $protectedAndUnchangedOnly);
    }

    /**
     * A live sync flushes the resolution cache after applying the
     * diff; a dry run leaves the memo intact. The observable
     * consequence is that a subsequent `rememberRoles` call invokes
     * its resolver post-sync (fresh read) but not post-dry-run
     * (memoised value returned).
     *
     * @return void
     */
    public function testLiveSyncFlushesResolutionCacheAndDryRunDoesNot(): void
    {
        $this->configureEnums([SyncStubPermission::class]);

        /** @var \SineMacula\Laravel\Authorization\Cache\ResolutionCache $cache */
        $cache     = $this->app->make(ResolutionCache::class); // @phpstan-ignore method.nonObject
        $principal = new \stdClass;

        // Warm the memo.
        $cache->rememberRoles($principal, static fn (): array => ['initial']);

        Artisan::call('authorization:sync', ['--dry-run' => true]);

        $calls = 0;

        $afterDryRun = $cache->rememberRoles($principal, static function () use (&$calls): array {
            $calls++;

            return ['stale'];
        });

        // Dry run does not flush — the memoised `initial` value comes
        // back without re-invoking the resolver.
        self::assertSame(['initial'], $afterDryRun);
        self::assertSame(0, $calls);

        Artisan::call('authorization:sync');

        $afterLive = $cache->rememberRoles($principal, static function () use (&$calls): array {
            $calls++;

            return ['reloaded'];
        });

        // Live sync flushed the memo — the resolver is invoked again.
        self::assertSame(['reloaded'], $afterLive);
        self::assertSame(1, $calls);
    }

    /**
     * Non-string and non-`PermissionEnum` entries in
     * `authorization.permission_enums` are silently skipped by the
     * command's defensive filter. Only the valid subclass contributes
     * rows, and the run exits cleanly.
     *
     * Two valid enum classes are configured alongside the invalid
     * entries so every valid class in the list contributes rows —
     * catches the `ArrayOneItem` mutation that would truncate the
     * filtered class list to the first entry only.
     *
     * @return void
     */
    public function testInvalidEnumEntriesAreSilentlySkipped(): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.permission_enums', [
            123,
            'NonexistentClass',
            \stdClass::class,
            SyncStubPermission::class,
            SyncStubSecondaryPermission::class,
        ]);

        Event::fake([PermissionCreated::class]);

        $exitCode = Artisan::call('authorization:sync');

        self::assertSame(0, $exitCode);

        // SyncStubPermission contributes three tuples (posts:view
        // web/api, posts:delete null). SyncStubSecondaryPermission
        // contributes one disjoint tuple (roles:assign web). Four
        // `Created` events fire — proves both enum classes walked,
        // not just the first (`ArrayOneItem` mutation on the
        // filtered class list would otherwise drop the secondary).
        Event::assertDispatchedTimes(PermissionCreated::class, 4);

        /** @var \Illuminate\Database\Eloquent\Collection<int, \SineMacula\Laravel\Authorization\Models\Permission> $rows */
        // @phpstan-ignore staticMethod.dynamicCall, staticMethod.dynamicCall
        $rows = Permission::withDeprecated()->orderBy('name')->orderBy('guard')->get();

        self::assertCount(4, $rows);
        self::assertSame(
            ['posts:delete', 'posts:view', 'posts:view', 'roles:assign'],
            $rows->pluck('name')->all(),
        );
    }

    /**
     * `--format=json` populates the `retire`, `protected`, and
     * `unchanged` bucket arrays with per-row objects carrying the
     * `name`, `guard`, and `action` keys.
     *
     * @return void
     */
    public function testJsonFormatDescribesRetireProtectedAndUnchangedBuckets(): void
    {
        // Seed the DB with the base enum state — three enum-backed
        // rows — then layer a system-flagged orphan for the
        // `protected` bucket on top.
        $this->configureEnums([SyncStubPermission::class]);
        Artisan::call('authorization:sync');

        Permission::create([
            'id'        => (string) Str::uuid(),
            'name'      => 'platform:admin',
            'guard'     => 'web',
            'is_system' => true,
        ]);

        // Swap in the reduced enum so `posts:delete` drops out and
        // lands in the `retire` bucket while both `posts:view` rows
        // stay `unchanged`.
        $this->configureEnums([SyncStubReducedPermission::class]);

        Artisan::call('authorization:sync', [
            '--dry-run' => true,
            '--format'  => 'json',
        ]);
        $output = Artisan::output();

        /** @var array<string, mixed>|null $payload */
        $payload = \json_decode($output, associative: true);

        self::assertIsArray($payload);
        /** @var array<string, mixed> $changes */
        $changes = $payload['changes']; // @phpstan-ignore offsetAccess.nonOffsetAccessible

        /** @var list<array<string, string|null>> $retire */
        $retire = $changes['retire']; // @phpstan-ignore offsetAccess.nonOffsetAccessible
        /** @var list<array<string, string|null>> $protectedBucket */
        $protectedBucket = $changes['protected']; // @phpstan-ignore offsetAccess.nonOffsetAccessible

        self::assertCount(1, $retire);
        self::assertSame('posts:delete', $retire[0]['name']);
        self::assertArrayHasKey('guard', $retire[0]);
        self::assertNull($retire[0]['guard']);
        self::assertSame('retire', $retire[0]['action']);

        self::assertCount(1, $protectedBucket);
        self::assertSame('platform:admin', $protectedBucket[0]['name']);
        self::assertSame('web', $protectedBucket[0]['guard']);
        self::assertSame('protected', $protectedBucket[0]['action']);
    }

    /**
     * `--format=json` populates the `update` and `reinstate` bucket
     * arrays with per-tuple describe objects carrying the exact
     * `name`, `guard`, and `action` keys — kills the
     * `UnwrapArrayMap` mutations that replace `array_map(describe)`
     * with the raw bucket payload (which carries row/tuple shapes,
     * not the describe-shape the JSON contract documents).
     *
     * @return void
     */
    public function testJsonFormatDescribesUpdateAndReinstateBuckets(): void
    {
        // Seed the DB with the base enum state — two `posts:view` rows
        // and the `posts:delete` row.
        $this->configureEnums([SyncStubPermission::class]);
        Artisan::call('authorization:sync');

        // Retire `posts:delete` so a dry-run swap later re-adds it as
        // a reinstate candidate.
        $this->configureEnums([SyncStubReducedPermission::class]);
        Artisan::call('authorization:sync');

        // Now swap in an enum that both drifts metadata on
        // `posts:view` (`update`) and re-adds `posts:delete`
        // (`reinstate`).
        $this->configureEnums([SyncStubUpdatedMetadataPermission::class]);

        Artisan::call('authorization:sync', [
            '--dry-run' => true,
            '--format'  => 'json',
        ]);
        $output = Artisan::output();

        /** @var array<string, mixed>|null $payload */
        $payload = \json_decode($output, associative: true);

        self::assertIsArray($payload);

        /** @var array<string, mixed> $changes */
        $changes = $payload['changes']; // @phpstan-ignore offsetAccess.nonOffsetAccessible

        /** @var list<array{name: string, guard: string|null, action: string}> $update */
        $update = $changes['update']; // @phpstan-ignore offsetAccess.nonOffsetAccessible
        /** @var list<array{name: string, guard: string|null, action: string}> $reinstate */
        $reinstate = $changes['reinstate']; // @phpstan-ignore offsetAccess.nonOffsetAccessible

        self::assertCount(2, $update);

        foreach ($update as $entry) {
            self::assertArrayHasKey('name', $entry);
            self::assertArrayHasKey('guard', $entry);
            self::assertArrayHasKey('action', $entry);
            self::assertSame('update', $entry['action']);
            self::assertSame('posts:view', $entry['name']);
        }

        $updateGuards = \array_column($update, 'guard');
        \sort($updateGuards);
        self::assertSame(['api', 'web'], $updateGuards);

        self::assertCount(1, $reinstate);
        self::assertArrayHasKey('name', $reinstate[0]);
        self::assertArrayHasKey('guard', $reinstate[0]);
        self::assertArrayHasKey('action', $reinstate[0]);
        self::assertSame('posts:delete', $reinstate[0]['name']);
        self::assertNull($reinstate[0]['guard']);
        self::assertSame('reinstate', $reinstate[0]['action']);
    }

    /**
     * Apply the given enum class list to `authorization.permission_enums`.
     *
     * @param  list<class-string>  $enums
     * @return void
     */
    private function configureEnums(array $enums): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app->make(ConfigRepository::class); // @phpstan-ignore method.nonObject
        $config->set('authorization.permission_enums', $enums);
    }
}
