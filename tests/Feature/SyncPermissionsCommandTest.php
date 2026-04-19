<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
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

        self::assertSame(0, $exitCode);
        Event::assertDispatchedTimes(PermissionDeprecated::class, 1);
        Event::assertNotDispatched(PermissionDeleted::class);

        $retired = Permission::withDeprecated()->where('name', 'posts:delete')->first();

        self::assertNotNull($retired);
        self::assertNotNull($retired->deprecated_at);
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

        self::assertSame(0, $exitCode);
        Event::assertDispatchedTimes(PermissionReinstated::class, 1);
        Event::assertDispatched(
            PermissionReinstated::class,
            static fn (PermissionReinstated $event): bool => $event->permission->name === 'posts:delete',
        );

        $fresh = Permission::where('name', 'posts:delete')->first();

        self::assertNotNull($fresh);
        self::assertNull($fresh->deprecated_at);
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

        self::assertSame(0, $exitCode);
        self::assertStringContainsString('Protected', Artisan::output());

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
     * `summary`, `changes`, and `dryRun` keys.
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
        self::assertSame(0, $summary['retire']);
        self::assertSame(0, $summary['roleReferences']);
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

        $exitCode = Artisan::call('authorization:sync');
        $output   = Artisan::output();

        self::assertSame(0, $exitCode);
        self::assertStringContainsString('Role references on retired', $output);
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
