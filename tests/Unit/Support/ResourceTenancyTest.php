<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use Illuminate\Database\Eloquent\Model;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceTenancy;
use Tests\Feature\Stubs\StubTenant;

/**
 * Unit tests for a queryable model's tenancy declaration.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ResourceTenancy::class)]
final class ResourceTenancyTest extends TestCase
{
    /**
     * A tenantless model's records have no tenant, whatever they hold, and it
     * keeps its tenant in no column.
     *
     * @return void
     */
    public function testATenantlessModelsRecordsHaveNoTenant(): void
    {
        $tenancy = ResourceTenancy::tenantless();

        self::assertTrue($tenancy->isTenantless());
        self::assertSame([], $tenancy->columnNames());
        self::assertNull($tenancy->tenantOf(self::record(['tenant_type' => 'teams', 'tenant_id' => '5'])));
    }

    /**
     * A model keeping its tenant in two columns reads both raw: a record of a
     * string or an integer key has that tenant, and one whose type or id is
     * null has none.
     *
     * @return void
     */
    public function testTwoColumnsAreReadRaw(): void
    {
        $tenancy = ResourceTenancy::columns('owner_type', 'owner_id');

        self::assertFalse($tenancy->isTenantless());
        self::assertSame(['owner_type', 'owner_id'], $tenancy->columnNames());
        self::assertSame(['owner_type', 'owner_id'], [$tenancy->typeColumn, $tenancy->idColumn]);
        self::assertEquals(new Reference('teams', '5'), $tenancy->tenantOf(self::record(['owner_type' => 'teams', 'owner_id' => 5])));
        self::assertEquals(new Reference('teams', 'a b'), $tenancy->tenantOf(self::record(['owner_type' => 'teams', 'owner_id' => 'a b'])));
        self::assertNull($tenancy->tenantOf(self::record(['owner_type' => null, 'owner_id' => '5'])));
        self::assertNull($tenancy->tenantOf(self::record(['owner_type' => 'teams', 'owner_id' => null])));
        self::assertSame(['tenant_type', 'tenant_id'], ResourceTenancy::columns()->columnNames());
    }

    /**
     * A model whose every tenant is of one type reads its key alone, the type
     * given as a morph type or as a model class.
     *
     * @return void
     */
    public function testAFixedTypeIsReadWithItsKey(): void
    {
        $tenancy = ResourceTenancy::ofType('teams', 'team_id');

        self::assertSame(['team_id'], $tenancy->columnNames());
        self::assertNull($tenancy->typeColumn);
        self::assertSame('teams', $tenancy->type);
        self::assertEquals(new Reference('teams', '7'), $tenancy->tenantOf(self::record(['team_id' => 7])));
        self::assertNull($tenancy->tenantOf(self::record(['team_id' => null])));
        self::assertSame((new StubTenant)->getMorphClass(), ResourceTenancy::ofType(StubTenant::class, 'tenant_id')->type);
    }

    /**
     * A record whose tenant column was not loaded, or holds anything but a
     * string or an integer, cannot be read; a tenant too long for a reference
     * is refused.
     *
     * @return void
     */
    public function testATenantThatCannotBeReadThrows(): void
    {
        $tenancy = ResourceTenancy::columns();

        foreach ([['tenant_type' => 'teams'], ['tenant_type' => 'teams', 'tenant_id' => 1.5], ['tenant_type' => true, 'tenant_id' => '5']] as $attributes) {
            try {
                $tenancy->tenantOf(self::record($attributes));

                self::fail('The tenant was read.');
            } catch (\UnexpectedValueException $exception) {
                self::assertStringContainsString('tenant column \'', $exception->getMessage());
            }
        }

        $this->expectException(\InvalidArgumentException::class);

        $tenancy->tenantOf(self::record(['tenant_type' => 'teams', 'tenant_id' => \str_repeat('x', 192)]));
    }

    /**
     * A fixed type that is empty, longer than a reference holds or holds a NUL
     * byte is refused, as is an empty column name.
     *
     * @return void
     */
    public function testAnInvalidDeclarationIsRefused(): void
    {
        foreach (['', \str_repeat('t', 192), "te\0ams"] as $type) {
            try {
                ResourceTenancy::ofType($type, 'team_id');

                self::fail('The type was accepted.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('A tenant type is 1 to 191 bytes with no NUL byte.', $exception->getMessage());
            }
        }

        self::assertSame(\str_repeat('t', 191), ResourceTenancy::ofType(\str_repeat('t', 191), 'team_id')->type);

        $this->expectExceptionMessage('A tenant column has a name.');

        ResourceTenancy::columns('tenant_type', '');
    }

    /**
     * Return a record holding the raw attributes.
     *
     * @param  array<string, mixed>  $attributes
     * @return \Illuminate\Database\Eloquent\Model
     */
    private static function record(array $attributes): Model
    {
        $record = new class extends Model {};

        $record->setRawAttributes($attributes);

        return $record;
    }
}
