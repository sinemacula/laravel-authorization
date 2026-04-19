<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Console\PrunePermissionsCommand;
use SineMacula\Laravel\Authorization\Events\Permission\Deleted as PermissionDeleted;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use Tests\TestCase;

/**
 * Feature tests for the `authorization:prune-deprecated` Artisan
 * command.
 *
 * Drives the full command surface through `Artisan::call` so the
 * tests track the public contract: exit codes, stdout shape,
 * emitted lifecycle events, pivot detachment, and survival of
 * active and system-protected rows.
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
     * A run against an empty candidate set is a clean no-op — exit 0
     * and zero counts across the summary.
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
        self::assertStringContainsString('Deprecated rows considered', $output);
    }

    /**
     * A deprecated row with no attached pivots is deleted and the
     * observer's `Permission\Deleted` event fires exactly once.
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
     * A deprecated row with role-permission pivots has its pivots
     * detached and the row deleted. The pivot table is empty for the
     * row afterwards.
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
     * `--dry-run` reports the candidate set, touches nothing, and
     * dispatches no `Permission\Deleted` events.
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
     * `is_system = true` rows are never candidates — even when
     * `deprecated_at` is set, the candidate filter excludes them,
     * they do not surface in the output, and they survive the run.
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
     * `--before=<date>` filters the candidate set to rows whose
     * `deprecated_at` is at or before the supplied instant. Rows
     * deprecated after the cutoff survive.
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
     * An unparseable `--before` value exits fatal (`2`) and the
     * offending value appears in the error message so operators can
     * diagnose their typo without re-reading the config.
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
     * `--format=json` emits a parseable payload carrying the
     * `summary`, `candidates`, and `dryRun` keys — matching the sync
     * command's JSON shape philosophy.
     *
     * @return void
     */
    public function testJsonFormatEmitsStructuredPayload(): void
    {
        $this->createDeprecatedPermission('posts:delete', 'web');

        Artisan::call('authorization:prune-deprecated', [
            '--dry-run' => true,
            '--format'  => 'json',
        ]);
        $output = Artisan::output();

        /** @var array<string, mixed>|null $payload */
        $payload = \json_decode($output, associative: true);

        self::assertIsArray($payload);
        self::assertArrayHasKey('dryRun', $payload);
        self::assertArrayHasKey('summary', $payload);
        self::assertArrayHasKey('candidates', $payload);
        self::assertTrue($payload['dryRun']);

        /** @var array<string, int> $summary */
        $summary = $payload['summary'];
        self::assertSame(1, $summary['considered']);
        self::assertSame(0, $summary['deleted']);
    }

    /**
     * An unknown `--format` is refused with a clear error and the
     * fatal exit code 2 — mirrors the sync command's contract so
     * pipeline parsers can share a single failure handler.
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
     * A live (non-deprecated) permission is never touched — the
     * `deprecated_at IS NOT NULL` predicate in the candidate query
     * guarantees prune cannot accidentally reap active rows.
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
     * Create a deprecated global permission row for the pruning
     * fixtures — centralises the `deprecated_at` stamping so the
     * tests stay focused on the behaviour under test.
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
