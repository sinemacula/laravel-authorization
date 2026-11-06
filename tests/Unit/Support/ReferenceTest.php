<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Cache\PrincipalCacheKey;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableTenant;
use SineMacula\Laravel\Authorization\Support\Reference;

/**
 * Unit tests for `Reference`, a record named by its morph type and key.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(Reference::class)]
final class ReferenceTest extends TestCase
{
    /**
     * Clear the morph map.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Relation::morphMap([], false);

        parent::tearDown();
    }

    /**
     * The reference answers its type and key as a model does, so the resolution
     * cache keys it as the grantee it names.
     *
     * @return void
     */
    public function testAnswersItsTypeAndKeyAsAModelDoes(): void
    {
        $reference = new Reference('user', '42');

        self::assertSame('user', $reference->getMorphClass());
        self::assertSame('42', $reference->getKey());
        self::assertSame('user:42', PrincipalCacheKey::for($reference));
    }

    /**
     * The reference is a tenant, answering the record's type and key as the
     * tenant's, so a tenant named by a reference can be a decision's tenant.
     *
     * @return void
     */
    public function testIsATenantNamedByItsTypeAndKey(): void
    {
        $tenant = new Reference('stub_tenant', '7');

        self::assertInstanceOf(AuthorizableTenant::class, $tenant);
        self::assertSame('stub_tenant', $tenant->getMorphClass());
        self::assertSame('7', $tenant->getKey());
    }

    /**
     * A type and a key of 191 bytes are accepted.
     *
     * @return void
     */
    public function testAcceptsATypeAndKeyOfTheMaximumLength(): void
    {
        $reference = new Reference(\str_repeat('t', 191), \str_repeat('k', 191));

        self::assertSame(191, \strlen($reference->type));
        self::assertSame(191, \strlen($reference->id));
        self::assertSame(191, Reference::MAX_BYTES);
    }

    /**
     * A type longer than 191 bytes is refused.
     *
     * @return void
     */
    public function testRefusesALongerType(): void
    {
        $this->expectExceptionObject(new \InvalidArgumentException('A reference\'s type and key are at most 191 bytes each.'));

        new Reference(\str_repeat('t', 192), '1');
    }

    /**
     * A key longer than 191 bytes is refused, counted in bytes rather than
     * characters.
     *
     * @return void
     */
    public function testRefusesALongerKeyCountedInBytes(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new Reference('user', \str_repeat('é', 96));
    }

    /**
     * A model is named by its morph class under the application's morph map and
     * its key as a string.
     *
     * @return void
     */
    public function testNamesAModelByItsMorphClassAndKey(): void
    {
        $model = new class extends Model {};

        $model->forceFill(['id' => 42]);

        self::assertEquals(new Reference($model::class, '42'), Reference::of($model));

        Relation::morphMap(['member' => $model::class]);

        self::assertEquals(new Reference('member', '42'), Reference::of($model));
    }

    /**
     * A model with no key is named with an empty key, and a reference is
     * returned as it is.
     *
     * @return void
     */
    public function testNamesAModelWithoutAKeyWithAnEmptyKey(): void
    {
        $reference = new Reference('user', '1');

        self::assertSame('', Reference::of(new class extends Model {})->id);
        self::assertSame($reference, Reference::of($reference));
    }

    /**
     * A record's tenant is read from its tenant columns, and a record the
     * platform owns has none.
     *
     * @return void
     */
    public function testReadsTheTenantOfARecord(): void
    {
        $owned    = (new class extends Model {})->forceFill(['tenant_type' => 'stub_tenant', 'tenant_id' => 7]);
        $platform = new class extends Model {};
        $partial  = (new class extends Model {})->forceFill(['tenant_type' => 'stub_tenant']);
        $odd      = (new class extends Model {})->forceFill(['tenant_type' => 7, 'tenant_id' => 'tenant-a']);

        self::assertEquals(new Reference('stub_tenant', '7'), Reference::tenantOf($owned));
        self::assertNull(Reference::tenantOf($platform));
        self::assertNull(Reference::tenantOf($partial));
        self::assertNull(Reference::tenantOf($odd));
    }
}
