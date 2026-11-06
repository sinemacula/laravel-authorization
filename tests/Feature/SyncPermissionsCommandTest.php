<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Console\Support\PermissionDiff;
use SineMacula\Laravel\Authorization\Console\Support\PermissionDiffBuilder;
use SineMacula\Laravel\Authorization\Console\SyncPermissionsCommand;
use SineMacula\Laravel\Authorization\Events\Permission\Created as PermissionCreated;
use SineMacula\Laravel\Authorization\Events\Permission\Deleted as PermissionDeleted;
use SineMacula\Laravel\Authorization\Events\Permission\Updated as PermissionUpdated;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Support\PermissionCatalogue;
use SineMacula\Laravel\Authorization\Support\PermissionDefinition;
use SineMacula\Laravel\Authorization\Support\PermissionMetadataReader;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\Concerns\ComparesReferences;
use Tests\Concerns\ReadsDispatchedEvents;
use Tests\Concerns\UsesAnAuthorizationConnection;
use Tests\Feature\Stubs\ConfigurablePermissionProvider;
use Tests\Feature\Stubs\CustomPermission;
use Tests\Feature\Stubs\Enums\CataloguePermission;
use Tests\Feature\Stubs\Enums\IntBackedPermissionEnum;
use Tests\Feature\Stubs\Enums\InvalidGuardsPermission;
use Tests\Feature\Stubs\Enums\InvalidNamePermission;
use Tests\Feature\Stubs\StubIdentity;
use Tests\TestCase;

/**
 * Feature tests for `authorization:sync`, which writes the permission catalogue
 * the configured enums and providers declare to the platform's rows.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(SyncPermissionsCommand::class)]
#[CoversClass(PermissionCatalogue::class)]
#[CoversClass(PermissionDiffBuilder::class)]
#[CoversClass(PermissionDiff::class)]
#[CoversClass(PermissionDefinition::class)]
#[CoversClass(PermissionMetadataReader::class)]
final class SyncPermissionsCommandTest extends TestCase
{
    use ComparesReferences, ReadsDispatchedEvents, UsesAnAuthorizationConnection;

    /** @var string The command's name. */
    private const string COMMAND = 'authorization:sync';

    /**
     * Declare the catalogue enum and the configurable provider, emptied.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        ConfigurablePermissionProvider::$permissions = [];

        $this->configure('authorization.permission_enums', [CataloguePermission::class]);
        $this->configure('authorization.permission_providers', [ConfigurablePermissionProvider::class]);
    }

    /**
     * A fresh catalogue is added, one row per case and guard, with each
     * declaration's metadata, the package's own permission among them, and each
     * addition runs the model's observers.
     *
     * @return void
     */
    public function testAddsTheDeclaredPermissions(): void
    {
        ConfigurablePermissionProvider::$permissions = [new PermissionDefinition(name: 'media:upload', description: 'Upload media', category: 'Media', guard: 'web')];

        Event::fake([PermissionCreated::class]);

        self::assertSame(0, Artisan::call(self::COMMAND));

        $output = Artisan::output();

        self::assertMatchesRegularExpression('/\|\s+Action\s+\|\s+Name\s+\|\s+Guard\s+\|\s+Category\s+\|\s+Description\s+\|/', $output);
        self::assertMatchesRegularExpression('/\|\s+add\s+\|\s+media:upload\s+\|\s+web\s+\|\s+Media\s+\|\s+Upload media\s+\|/', $output);
        self::assertMatchesRegularExpression('/\|\s+add\s+\|\s+posts:archive\s+\|\s+\(any\)\s+\|\s+\|\s+\|/', $output);
        self::assertMatchesRegularExpression('/\|\s+add\s+\|\s+authorization:guardrails:manage\s+\|\s+\(any\)\s+\|\s+authorization\s+\|/', $output);
        self::assertStringContainsString("\nadd: 6, update: 0, stale: 0, prune: 0, protected: 0, unchanged: 0.", $output);

        self::assertSame(
            [
                ['authorization:guardrails:manage', null, 'Set and remove guardrails from above the scope they cap.', 'authorization', false],
                ['media:upload', 'web', 'Upload media', 'Media', false],
                ['posts.publish', 'api', 'Publish posts', 'Posts', false],
                ['posts.publish', 'web', 'Publish posts', 'Posts', false],
                ['posts:archive', null, null, null, false],
                ['posts:create', null, 'Create posts', 'Posts', false],
            ],
            self::platformRows(),
        );

        Event::assertDispatchedTimes(PermissionCreated::class, 6);
    }

    /**
     * A second run changes nothing and lists every row as unchanged.
     *
     * @return void
     */
    public function testASecondRunChangesNothing(): void
    {
        Artisan::call(self::COMMAND);

        Event::fake([PermissionCreated::class, PermissionUpdated::class, PermissionDeleted::class]);

        self::assertSame(0, Artisan::call(self::COMMAND, ['--prune' => true]));
        self::assertStringContainsString('add: 0, update: 0, stale: 0, prune: 0, protected: 0, unchanged: 5.', Artisan::output());

        Event::assertNothingDispatched();
    }

    /**
     * A row whose description and category differ is updated through the model,
     * so its observers run.
     *
     * @return void
     */
    public function testUpdatesTheDescriptionAndTheCategory(): void
    {
        $row = Permission::create(['name' => 'posts:create', 'description' => 'Write posts', 'category' => 'Content']);

        Event::fake([PermissionUpdated::class]);

        self::assertSame(0, Artisan::call(self::COMMAND));
        self::assertMatchesRegularExpression('/\|\s+update\s+\|\s+posts:create\s+\|\s+\(any\)\s+\|\s+Posts\s+\|\s+Create posts\s+\|/', Artisan::output());

        $row->refresh();

        self::assertSame('Create posts', $row->description);
        self::assertSame('Posts', $row->category);

        Event::assertDispatched(PermissionUpdated::class, static fn (PermissionUpdated $event): bool => self::refersTo($event->permission, $row));
    }

    /**
     * A declaration that drops its description and category clears both
     * columns, so a second dry run finds nothing to change.
     *
     * @return void
     */
    public function testClearsTheDescriptionAndTheCategoryADeclarationDrops(): void
    {
        $row = Permission::create(['name' => 'posts:archive', 'description' => 'Old', 'category' => 'X']);

        self::assertSame(0, Artisan::call(self::COMMAND));
        self::assertMatchesRegularExpression('/\|\s+update\s+\|\s+posts:archive\s+\|\s+\(any\)\s+\|\s+\|\s+\|/', Artisan::output());

        $row->refresh();

        self::assertNull($row->description);
        self::assertNull($row->category);

        self::assertSame(0, Artisan::call(self::COMMAND, ['--dry-run' => true]));
        self::assertMatchesRegularExpression('/\|\s+unchanged\s+\|\s+posts:archive\s+\|/', Artisan::output());
    }

    /**
     * An undeclared row is reported as stale and left alone.
     *
     * @return void
     */
    public function testReportsAStaleRowWithoutTouchingIt(): void
    {
        $stale = Permission::create(['name' => 'posts:purge', 'description' => 'Purge posts']);

        self::assertSame(0, Artisan::call(self::COMMAND));

        $output = Artisan::output();

        self::assertMatchesRegularExpression('/\|\s+stale\s+\|\s+posts:purge\s+\|\s+\(any\)\s+\|\s+\|\s+Purge posts\s+\|/', $output);
        self::assertStringContainsString('add: 5, update: 0, stale: 1, prune: 0, protected: 0, unchanged: 0.', $output);
        self::assertTrue(Permission::query()->whereKey($stale->getKey())->exists());
    }

    /**
     * With `--prune`, a stale row is deleted through the model, so its
     * observers run, and a stale system row is reported as protected and kept.
     *
     * @return void
     */
    public function testPruneDeletesStaleRowsButNotSystemRows(): void
    {
        $stale  = Permission::create(['name' => 'posts:purge']);
        $system = Permission::create(['name' => 'posts:*', 'is_system' => true]);

        Event::fake([PermissionDeleted::class]);

        self::assertSame(0, Artisan::call(self::COMMAND, ['--prune' => true]));

        $output = Artisan::output();

        self::assertMatchesRegularExpression('/\|\s+prune\s+\|\s+posts:purge\s+\|/', $output);
        self::assertMatchesRegularExpression('/\|\s+protected\s+\|\s+posts:\*\s+\|/', $output);
        self::assertFalse(Permission::query()->whereKey($stale->getKey())->exists());
        self::assertTrue(Permission::query()->whereKey($system->getKey())->exists());

        Event::assertDispatchedTimes(PermissionDeleted::class, 1);
        Event::assertDispatched(PermissionDeleted::class, static fn (PermissionDeleted $event): bool => self::refersTo($event->permission, $stale));
    }

    /**
     * A system row declared with different metadata is reported as protected
     * and not edited.
     *
     * @return void
     */
    public function testLeavesADeclaredSystemRowAlone(): void
    {
        $system = Permission::create(['name' => 'posts:create', 'description' => 'Platform post creation', 'is_system' => true]);

        self::assertSame(0, Artisan::call(self::COMMAND));
        self::assertMatchesRegularExpression('/\|\s+protected\s+\|\s+posts:create\s+\|/', Artisan::output());
        self::assertSame('Platform post creation', $system->refresh()->description);
    }

    /**
     * Tenant-owned permissions are neither read nor changed, even when one
     * shares a declared permission's name or no enum declares it.
     *
     * @return void
     */
    public function testNeverReadsOrChangesTenantRows(): void
    {
        $shared     = Permission::create(['name' => 'posts:create', 'description' => 'Tenant posts', 'tenant_type' => 'tenant', 'tenant_id' => 't1']);
        $undeclared = Permission::create(['name' => 'tenant:only', 'tenant_type' => 'tenant', 'tenant_id' => 't1']);

        self::assertSame(0, Artisan::call(self::COMMAND, ['--prune' => true]));

        $output = Artisan::output();

        self::assertStringNotContainsString('tenant:only', $output);
        self::assertStringContainsString('add: 5, update: 0, stale: 0, prune: 0, protected: 0, unchanged: 0.', $output);

        $tenantRows = Permission::query()->withoutGlobalScope(TenantScope::class)->whereNotNull('tenant_type');

        self::assertSame([$shared->getKey(), $undeclared->getKey()], $tenantRows->orderBy('name')->pluck('id')->all());
        self::assertSame('Tenant posts', $shared->refresh()->description);
    }

    /**
     * A dry run that finds permissions to add writes nothing and exits with the
     * drift code.
     *
     * @return void
     */
    public function testDryRunWithAdditionsWritesNothingAndExitsWithDrift(): void
    {
        self::assertSame(1, Artisan::call(self::COMMAND, ['--dry-run' => true]));
        self::assertStringContainsString('Dry run, nothing was written. add: 5, update: 0, stale: 0, prune: 0, protected: 0, unchanged: 0.', Artisan::output());
        self::assertSame([], self::platformRows());
    }

    /**
     * A dry run that finds a row to update exits with the drift code and leaves
     * the row as it was.
     *
     * @return void
     */
    public function testDryRunWithAnUpdateExitsWithDrift(): void
    {
        Artisan::call(self::COMMAND);

        $row = Permission::query()->where('name', 'posts:create')->firstOrFail();
        $row->fill(['description' => 'Write posts'])->save();

        self::assertSame(1, Artisan::call(self::COMMAND, ['--dry-run' => true]));
        self::assertSame('Write posts', $row->refresh()->description);
    }

    /**
     * A dry run that would prune exits with the drift code and deletes nothing;
     * without `--prune` a stale row is not drift.
     *
     * @return void
     */
    public function testDryRunCountsStaleRowsAsDriftOnlyWhenPruning(): void
    {
        Artisan::call(self::COMMAND);

        $stale = Permission::create(['name' => 'posts:purge']);

        self::assertSame(0, Artisan::call(self::COMMAND, ['--dry-run' => true]));
        self::assertSame(1, Artisan::call(self::COMMAND, ['--dry-run' => true, '--prune' => true]));
        self::assertTrue(Permission::query()->whereKey($stale->getKey())->exists());
    }

    /**
     * A dry run against a synced catalogue exits with success.
     *
     * @return void
     */
    public function testDryRunWithoutDriftSucceeds(): void
    {
        Artisan::call(self::COMMAND);

        self::assertSame(0, Artisan::call(self::COMMAND, ['--dry-run' => true]));
    }

    /**
     * With `--format=json` every row is listed with its action, after the run's
     * mode and a count per action.
     *
     * @return void
     */
    public function testRendersJson(): void
    {
        $this->configure('authorization.permission_enums', []);

        ConfigurablePermissionProvider::$permissions = [new PermissionDefinition(name: 'media:upload', description: 'Read/write media', category: 'Media', guard: 'web')];

        Permission::create(['name' => 'media:purge']);

        self::assertSame(1, Artisan::call(self::COMMAND, ['--format' => 'json', '--dry-run' => true, '--prune' => true]));

        $expected = [
            'dry_run'     => true,
            'prune'       => true,
            'summary'     => ['add' => 2, 'update' => 0, 'stale' => 0, 'prune' => 1, 'protected' => 0, 'unchanged' => 0],
            'permissions' => [
                [
                    'action'      => 'add',
                    'name'        => 'authorization:guardrails:manage',
                    'guard'       => null,
                    'description' => 'Set and remove guardrails from above the scope they cap.',
                    'category'    => 'authorization',
                ],
                ['action' => 'add', 'name' => 'media:upload', 'guard' => 'web', 'description' => 'Read/write media', 'category' => 'Media'],
                ['action' => 'prune', 'name' => 'media:purge', 'guard' => null, 'description' => null, 'category' => null],
            ],
        ];

        self::assertSame(\json_encode($expected, \JSON_THROW_ON_ERROR | \JSON_PRETTY_PRINT | \JSON_UNESCAPED_SLASHES) . "\n", Artisan::output());
    }

    /**
     * The rows are listed by action, in the order add, update, stale or prune,
     * protected, unchanged, then by name and guard within an action.
     *
     * @return void
     */
    public function testListsTheRowsByActionThenNameThenGuard(): void
    {
        Permission::create(['name' => 'posts:archive']);
        Permission::create(['name' => 'posts.publish', 'guard' => 'web', 'description' => 'Publish posts', 'category' => 'Posts']);
        Permission::create(['name' => 'posts:create', 'description' => 'Write posts', 'category' => 'Posts']);
        Permission::create(['name' => 'posts:*', 'is_system' => true]);
        Permission::create(['name' => 'posts:purge']);
        Permission::create(['name' => 'posts:empty']);

        $expected = [
            ['add', 'authorization:guardrails:manage', null, 'Set and remove guardrails from above the scope they cap.', 'authorization'],
            ['add', 'posts.publish', 'api', 'Publish posts', 'Posts'],
            ['update', 'posts:create', null, 'Create posts', 'Posts'],
            ['prune', 'posts:empty', null, null, null],
            ['prune', 'posts:purge', null, null, null],
            ['protected', 'posts:*', null, null, null],
            ['unchanged', 'posts.publish', 'web', 'Publish posts', 'Posts'],
            ['unchanged', 'posts:archive', null, null, null],
        ];

        self::assertSame(1, Artisan::call(self::COMMAND, ['--format' => 'json', '--dry-run' => true, '--prune' => true]));
        self::assertSame($expected, self::listedRows());

        $expected[3][0] = 'stale';
        $expected[4][0] = 'stale';

        self::assertSame(1, Artisan::call(self::COMMAND, ['--format' => 'json', '--dry-run' => true]));
        self::assertSame($expected, self::listedRows());
    }

    /**
     * JSON output of a writing run reports the mode it ran in, and the
     * package's own permission once it is synced.
     *
     * @return void
     */
    public function testRendersJsonForAWritingRun(): void
    {
        $this->configure('authorization.permission_enums', []);

        self::assertSame(0, Artisan::call(self::COMMAND, ['--format' => 'json']));

        $output = Artisan::output();

        /** @var array{dry_run: bool, prune: bool, permissions: list<mixed>} $payload */
        $payload = \json_decode($output, true, flags: \JSON_THROW_ON_ERROR);

        self::assertFalse($payload['dry_run']);
        self::assertFalse($payload['prune']);
        $package = ['add', 'authorization:guardrails:manage', null, 'Set and remove guardrails from above the scope they cap.', 'authorization'];

        self::assertSame([$package], self::listedRows($output));
    }

    /**
     * An unknown format, or none, is a fatal error and nothing is written.
     *
     * @return void
     */
    public function testRefusesAnUnknownFormat(): void
    {
        self::assertSame(2, Artisan::call(self::COMMAND, ['--format' => 'xml']));
        self::assertStringContainsString('Unknown format \'xml\': expected \'table\' or \'json\'.', Artisan::output());

        self::assertSame(2, Artisan::call(self::COMMAND, ['--format' => null]));
        self::assertStringContainsString('Unknown format \'\': expected \'table\' or \'json\'.', Artisan::output());

        self::assertSame([], self::platformRows());
    }

    /**
     * A declared name that breaks the name rules is a fatal error, and none of
     * the catalogue is written.
     *
     * @return void
     */
    public function testRefusesAnInvalidNameWithoutWritingAnything(): void
    {
        $this->configure('authorization.permission_enums', [CataloguePermission::class, InvalidNamePermission::class]);

        self::assertSame(2, Artisan::call(self::COMMAND));
        self::assertStringContainsString(
            'Nothing was synced: Invalid permission declared by ' . InvalidNamePermission::class . '::SPACED: \'reports edit\' is not a valid permission name',
            Artisan::output(),
        );
        self::assertSame([], self::platformRows());
    }

    /**
     * A guard that is not a non-empty string is a fatal error naming the case,
     * and nothing is written, not even the guard-agnostic row a null guard
     * would otherwise read as.
     *
     * @return void
     */
    public function testRefusesAnInvalidGuardWithoutWritingAnything(): void
    {
        $this->configure('authorization.permission_enums', [CataloguePermission::class, InvalidGuardsPermission::class]);

        self::assertSame(2, Artisan::call(self::COMMAND));
        self::assertStringContainsString(
            'Nothing was synced: Invalid permission declared by ' . InvalidGuardsPermission::class . '::NULL_GUARD: every guard must be a non-empty string, got null;',
            Artisan::output(),
        );
        self::assertSame([], self::platformRows());
    }

    /**
     * Configuration the boot validation would refuse is refused at run time
     * too.
     *
     * @return void
     */
    public function testRefusesInvalidConfiguration(): void
    {
        $this->configure('authorization.permission_enums', [IntBackedPermissionEnum::class]);

        self::assertSame(2, Artisan::call(self::COMMAND));
        self::assertStringContainsString('Nothing was synced: Invalid authorization config at \'authorization.permission_enums.0\'', Artisan::output());
    }

    /**
     * Rows are written through the configured permission model.
     *
     * @return void
     */
    public function testWritesThroughTheConfiguredModel(): void
    {
        $this->configure('authorization.models.permission', CustomPermission::class);

        Permission::create(['name' => 'posts:purge']);

        Event::fake([PermissionCreated::class, PermissionDeleted::class]);

        self::assertSame(0, Artisan::call(self::COMMAND, ['--prune' => true]));

        Event::assertDispatched(PermissionCreated::class, static fn (PermissionCreated $event): bool => $event->permission->type === (new CustomPermission)->getMorphClass());
        Event::assertNotDispatched(PermissionCreated::class, static fn (PermissionCreated $event): bool => $event->permission->type !== (new CustomPermission)->getMorphClass());
        Event::assertDispatched(PermissionDeleted::class, static fn (PermissionDeleted $event): bool => $event->permission->type === (new CustomPermission)->getMorphClass());
    }

    /**
     * Rows are written on the package's connection when one is configured.
     *
     * @return void
     */
    public function testWritesOnTheConfiguredConnection(): void
    {
        $this->useAnAuthorizationConnection();

        self::assertSame(0, Artisan::call(self::COMMAND));

        self::assertSame(5, self::authorizationConnection()->table('permissions')->count());
        self::assertSame(0, DB::connection('testing')->table('permissions')->count());
    }

    /**
     * A write that fails part-way rolls back every write before it, on the
     * package's connection, and is a fatal error.
     *
     * @return void
     */
    public function testRollsBackWhenAWriteFailsPartWay(): void
    {
        $this->useAnAuthorizationConnection();

        $updated = Permission::create(['name' => 'posts:create', 'description' => 'Write posts']);
        $stale   = Permission::create(['name' => 'posts:purge']);

        Permission::deleting(static function (): never {
            throw new \RuntimeException('The delete failed.');
        });

        self::assertSame(2, Artisan::call(self::COMMAND, ['--prune' => true]));
        self::assertStringContainsString('Nothing was synced: The delete failed.', Artisan::output());

        self::assertSame(
            [['posts:create', null, 'Write posts', null, false], ['posts:purge', null, null, null, false]],
            self::platformRows(),
        );
        self::assertSame('Write posts', $updated->refresh()->description);
        self::assertTrue(Permission::query()->whereKey($stale->getKey())->exists());
    }

    /**
     * A sync is one operation: every event its writes dispatch shares one
     * operation id and carries the actor `--actor` names, once the sync
     * commits; a second sync is an operation of its own, with no actor.
     *
     * @return void
     */
    public function testASyncIsOneOperationForTheActorTheOptionNames(): void
    {
        StubIdentity::query()->create(['id' => 'admin-1']);

        Event::fake([PermissionCreated::class, PermissionDeleted::class]);

        self::assertSame(0, Artisan::call(self::COMMAND, ['--actor' => StubIdentity::class . ':admin-1']));

        $created = self::dispatchedEvents(PermissionCreated::class);

        self::assertCount(5, $created);
        self::assertCount(1, \array_unique(\array_map(static fn (PermissionCreated $event): string => $event->operation->id, $created)));

        foreach ($created as $event) {
            self::assertTrue(self::refersTo($event->operation->actor, new Reference(StubIdentity::class, 'admin-1')));
        }

        $this->configure('authorization.permission_enums', []);

        self::assertSame(0, Artisan::call(self::COMMAND, ['--prune' => true]));

        $deleted = self::dispatchedEvents(PermissionDeleted::class);

        self::assertCount(4, $deleted);
        self::assertNotContains($deleted[0]->operation->id, \array_map(static fn (PermissionCreated $event): string => $event->operation->id, $created));
        self::assertNull($deleted[0]->operation->actor);
    }

    /**
     * An actor the option cannot resolve fails the sync and writes nothing.
     *
     * @return void
     */
    public function testFailsOnAnActorItCannotResolve(): void
    {
        self::assertSame(2, Artisan::call(self::COMMAND, ['--actor' => StubIdentity::class . ':ghost']));
        self::assertStringContainsString('Nothing was synced: No actor', Artisan::output());
        self::assertSame([], self::platformRows());
    }

    /**
     * Set a configuration value.
     *
     * @param  string  $key
     * @param  mixed  $value
     * @return void
     */
    private function configure(string $key, mixed $value): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = $this->app?->make(ConfigRepository::class);

        $config->set($key, $value);
    }

    /**
     * Return the rows the last JSON run listed, each as `[action, name, guard,
     * description, category]`.
     *
     * @param  string|null  $output
     * @return list<array{string, string, string|null, string|null, string|null}>
     */
    private static function listedRows(?string $output = null): array
    {
        /** @var array{permissions: list<array{action: string, name: string, guard: string|null, description: string|null, category: string|null}>} $payload */
        $payload = \json_decode($output ?? Artisan::output(), true, flags: \JSON_THROW_ON_ERROR);

        return \array_map(
            static fn (array $entry): array => [$entry['action'], $entry['name'], $entry['guard'], $entry['description'], $entry['category']],
            $payload['permissions'],
        );
    }

    /**
     * Return every platform permission row as `[name, guard, description,
     * category, system]`, ordered by name and guard by byte value, with the
     * guard-agnostic row first.
     *
     * The rows are sorted here rather than by the database, whose collation may
     * ignore punctuation or place nulls last.
     *
     * @return list<array{string, string|null, string|null, string|null, bool}>
     */
    private static function platformRows(): array
    {
        $rows = Permission::query()
            ->withoutGlobalScope(TenantScope::class)
            ->whereNull('tenant_type')
            ->get()
            ->map(static fn (Permission $row): array => [$row->name, $row->guard, $row->description, $row->category, $row->is_system])
            ->all();

        \usort($rows, static fn (array $left, array $right): int => \strcmp($left[0], $right[0]) ?: \strcmp($left[1] ?? '', $right[1] ?? ''));

        return $rows;
    }
}
