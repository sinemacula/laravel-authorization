<?php

declare(strict_types = 1);

namespace Tests\Feature\Services;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Exceptions\InvalidGrantTargetException;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Scopes\TenantScope;
use SineMacula\Laravel\Authorization\Services\Support\StoredRecords;
use SineMacula\Laravel\Authorization\Support\Reference;
use Tests\TestCase;

/**
 * Feature tests for `StoredRecords`: the role, permission or policy a delegated
 * change hands out, read as stored.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(StoredRecords::class)]
final class StoredRecordsTest extends TestCase
{
    /**
     * The row is read again by its key, as a new instance, discarding what the
     * model in hand changed and did not save, whatever tenant scope is in
     * place, so a row another tenant owns is still read.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheRowIsReadAsStored(): void
    {
        $role       = Role::query()->withoutGlobalScopes()->create(['name' => 'editor', 'rank' => 7, 'tenant_type' => 'tenant', 'tenant_id' => 'a']);
        $role->rank = 0;

        $stored = TenantScope::within(new Reference('tenant', 'b'), null, static fn (): Role => StoredRecords::of('role', $role));

        self::assertNotSame($role, $stored);
        self::assertSame(7, $stored->rank);
        self::assertSame($role->getKey(), $stored->getKey());
        self::assertSame(0, $role->rank);
    }

    /**
     * The model a caller handed a change takes on the record the change wrote:
     * its attributes, as the original, whether it exists and whether it was
     * just created; a model that is the record is returned as it is.
     *
     * @return void
     */
    public function testTheModelGivenTakesOnTheRecordWritten(): void
    {
        $given        = new Role(['name' => 'draft']);
        $given->rank  = 3;
        $record       = Role::query()->create(['name' => 'editor', 'rank' => 7]);
        $record->rank = 8;

        self::assertSame($given, StoredRecords::adopt($given, $record));
        self::assertSame($record->getAttributes(), $given->getAttributes());
        self::assertSame($record->getAttributes(), $given->getRawOriginal());
        self::assertTrue($given->exists);
        self::assertTrue($given->wasRecentlyCreated);

        $record->delete();

        StoredRecords::adopt($given, $record);

        self::assertFalse($given->exists);
        self::assertSame($record, StoredRecords::adopt($record, $record));
        self::assertSame(8, $record->rank);
    }

    /**
     * A model whose row is gone is refused as an invalid target of its kind.
     *
     * @return void
     */
    public function testARowThatIsGoneIsRefused(): void
    {
        $policy = Policy::query()->create(['name' => 'gone', 'document' => ['statements' => []]]);

        DB::table('policies')->where('id', $policy->getKey())->delete();

        try {
            StoredRecords::of('policy', $policy);
            self::fail('A policy whose row is gone was read.');
        } catch (InvalidGrantTargetException $exception) {
            self::assertSame('policy', $exception->getKind());
        }
    }
}
