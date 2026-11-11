<?php

declare(strict_types = 1);

namespace Tests\Feature\Support;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authorization\Exceptions\InvalidTenantColumnsException;
use SineMacula\Laravel\Authorization\Exceptions\OwnerChangedException;
use SineMacula\Laravel\Authorization\Models\Permission;
use SineMacula\Laravel\Authorization\Models\Policy;
use SineMacula\Laravel\Authorization\Models\Role;
use SineMacula\Laravel\Authorization\Support\RecordOwner;
use Tests\Concerns\CatchesRefusals;
use Tests\TestCase;

/**
 * Feature tests for the rules every role, permission and policy keeps about its
 * owner: both tenant columns or neither, and an owner fixed once created.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecordOwner::class)]
final class RecordOwnerTest extends TestCase
{
    use CatchesRefusals;

    /**
     * One tenant column without the other is refused, naming the one missing.
     *
     * @return void
     */
    public function testOneTenantColumnWithoutTheOtherIsRefused(): void
    {
        foreach ([['tenant_type' => 'stub_tenant'], ['tenant_id' => 'tenant-a']] as $columns) {
            try {
                RecordOwner::assertValid(new Role(['name' => 'editor', ...$columns]), 'role');
                self::fail('One tenant column was accepted.');
            } catch (InvalidTenantColumnsException $exception) {
                self::assertStringContainsString(isset($columns['tenant_type']) ? 'tenant_id' : 'tenant_type', $exception->getMessage());
            }
        }

        RecordOwner::assertValid(new Role(['name' => 'editor']), 'role');
        RecordOwner::assertValid(new Role(['name' => 'editor', 'tenant_type' => 'stub_tenant', 'tenant_id' => 'tenant-a']), 'role');
    }

    /**
     * A row naming half a tenant is refused for the action named, saving by
     * default, naming the column it lacks; a whole tenant and the platform
     * pass.
     *
     * @return void
     */
    public function testARowNamingHalfATenantIsRefusedForTheActionNamed(): void
    {
        $granted = self::refusalOf(static fn () => RecordOwner::assertWhole(new Role(['name' => 'editor', 'tenant_id' => 'tenant-a']), 'role', 'grant'));
        $saved   = self::refusalOf(static fn () => RecordOwner::assertWhole(new Role(['name' => 'editor', 'tenant_type' => 'stub_tenant']), 'role'));

        self::assertInstanceOf(InvalidTenantColumnsException::class, $granted);
        self::assertStringStartsWith('Cannot grant role with inconsistent tenant columns — \'tenant_type\' is required', $granted->getMessage());
        self::assertInstanceOf(InvalidTenantColumnsException::class, $saved);
        self::assertStringStartsWith('Cannot save role with inconsistent tenant columns — \'tenant_id\' is required', $saved->getMessage());

        RecordOwner::assertWhole(new Role(['name' => 'editor']), 'role', 'grant');
        RecordOwner::assertWhole(new Role(['name' => 'editor', 'tenant_type' => 'stub_tenant', 'tenant_id' => 'tenant-a']), 'role', 'grant');
    }

    /**
     * A saved role, permission or policy cannot change its owner, either way,
     * though anything else about it may change.
     *
     * @return void
     */
    public function testASavedRecordKeepsItsOwner(): void
    {
        $records = [
            'role'       => Role::query()->create(['name' => 'editor']),
            'permission' => Permission::query()->create(['name' => 'posts:edit', 'tenant_type' => 'stub_tenant', 'tenant_id' => 'tenant-a']),
            'policy'     => Policy::query()->create(['name' => 'readers', 'document' => ['version' => 1, 'statements' => []]]),
        ];

        foreach ($records as $kind => $record) {
            $record->setAttribute('description', 'Changed');
            $record->save();

            $record->forceFill($record->getAttribute('tenant_type') === null
                ? ['tenant_type' => 'stub_tenant', 'tenant_id' => 'tenant-b']
                : ['tenant_type' => null, 'tenant_id' => null]);

            $refusal = self::refusalOf(static fn (): bool => $record->save());

            self::assertInstanceOf(OwnerChangedException::class, $refusal);
            self::assertSame($kind, $refusal->getKind());
            self::assertSame($record->getAttribute('name'), $refusal->getName());
        }
    }
}
