<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Enums\GrantOutcome;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Observers\Support\RecordChanges;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\TestCase;

/**
 * Feature tests for `RecordChanges`, which holds what the record observers read
 * before a write until its event is built.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(RecordChanges::class)]
final class RecordChangesTest extends TestCase
{
    /**
     * The changed fields are reported before and after the update as plain
     * values: scalars as they are, dates as ISO 8601 strings in UTC, backed
     * enums as their values and anything else as null.
     *
     * @return void
     */
    public function testReportsTheChangedFieldsAsPlainValues(): void
    {
        $model = self::model([
            'name'    => 'editor',
            'rank'    => 1,
            'when'    => '2026-07-01 12:00:00',
            'outcome' => 'granted',
            'meta'    => '{"a":1}',
            'at'      => null,
            'kept'    => 'same',
        ]);

        $model->forceFill([
            'name'    => 'author',
            'rank'    => 2,
            'when'    => '2026-08-01 12:00:00',
            'outcome' => GrantOutcome::REARMED,
            'meta'    => ['a' => 2],
            'at'      => new \DateTimeImmutable('2026-08-01 14:00:00', new \DateTimeZone('Europe/Paris')),
        ]);

        RecordChanges::capture($model);

        self::assertSame([
            'before' => ['name' => 'editor', 'rank' => 1, 'when' => '2026-07-01T12:00:00+00:00', 'outcome' => 'granted', 'meta' => null, 'at' => null],
            'after'  => ['name' => 'author', 'rank' => 2, 'when' => '2026-08-01T12:00:00+00:00', 'outcome' => 'rearmed', 'meta' => null, 'at' => '2026-08-01T12:00:00+00:00'],
        ], RecordChanges::diff($model));
    }

    /**
     * The fields named as excluded are left out, and a diff forgets the
     * capture, so a second diff reports nothing.
     *
     * @return void
     */
    public function testLeavesOutTheExcludedFieldsAndForgetsTheCapture(): void
    {
        $model = self::model(['name' => 'editor', 'rank' => 1]);

        $model->forceFill(['name' => 'author', 'rank' => 2]);

        RecordChanges::capture($model, ['rank']);

        self::assertSame(['before' => ['name' => 'editor'], 'after' => ['name' => 'author']], RecordChanges::diff($model));
        self::assertSame(['before' => [], 'after' => []], RecordChanges::diff($model));
    }

    /**
     * What is held for a write is released once, for that model only.
     *
     * @return void
     */
    public function testReleasesWhatWasHeldOnce(): void
    {
        $first  = self::model([]);
        $second = self::model([]);

        RecordChanges::hold($first, ['grantees' => ['a']]);

        self::assertSame([], RecordChanges::release($second));
        self::assertSame(['grantees' => ['a']], RecordChanges::release($first));
        self::assertSame([], RecordChanges::release($first));
    }

    /**
     * The rows a relation links to are read from the pivot table and named by
     * the related model's morph class, whichever tenant owns them.
     *
     * @return void
     */
    public function testListsTheLinkedRowsFromThePivotTable(): void
    {
        $role     = Role::query()->create(['name' => 'editor', 'tenant_type' => 'stub_tenant', 'tenant_id' => 'tenant-a']);
        $platform = Permission::query()->create(['name' => 'posts:edit']);
        $tenant   = Permission::query()->create(['name' => 'posts:delete', 'tenant_type' => 'stub_tenant', 'tenant_id' => 'tenant-a']);

        $role->permissions()->attach([$platform->id, $tenant->id]);

        $linked = RecordChanges::linked($role->permissions());

        \usort($linked, static fn (Reference $a, Reference $b): int => $a->id <=> $b->id);

        $expected = [Reference::of($platform), Reference::of($tenant)];

        \usort($expected, static fn (Reference $a, Reference $b): int => $a->id <=> $b->id);

        self::assertEquals($expected, $linked);
        self::assertSame(2, DB::table('role_permissions')->count());
    }

    /**
     * Return an unsaved model whose original attributes are the given ones.
     *
     * @param  array<string, mixed>  $original
     * @return \Illuminate\Database\Eloquent\Model
     */
    private static function model(array $original): Model
    {
        $model = new class extends Model {
            /**
             * Return the attribute casts.
             *
             * @return array<string, string>
             */
            #[\Override]
            protected function casts(): array
            {
                return ['when' => 'immutable_datetime', 'outcome' => GrantOutcome::class, 'meta' => 'array'];
            }
        };

        return $model->setRawAttributes($original, true);
    }
}
