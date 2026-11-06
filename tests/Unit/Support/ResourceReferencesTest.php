<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use Illuminate\Container\Container;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableResource;
use SineMacula\Laravel\Authorization\Contracts\ResourceTenantResolver;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceReference;
use SineMacula\Laravel\Authorization\Support\ResourceReferences;
use Tests\Feature\Stubs\FixedResourceTenantResolver;
use Tests\Feature\Stubs\StubTenant;

/**
 * Unit tests for `ResourceReferences`, which turns the value a check is about
 * into the reference of its resource.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(ResourceReferences::class)]
final class ResourceReferencesTest extends TestCase
{
    /** @var \Tests\Feature\Stubs\FixedResourceTenantResolver The resource tenant resolver bound for the test. */
    private FixedResourceTenantResolver $resolver;

    /**
     * Bind a resource tenant resolver that knows no model's tenant, in a fresh
     * container.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Container::setInstance(new Container);

        $this->bindResolver(null);
    }

    /**
     * Forget the container and clear the morph map.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Container::setInstance(null);
        Relation::morphMap([], false);

        parent::tearDown();
    }

    /**
     * No value is no resource, and a reference is returned as it is.
     *
     * @return void
     */
    public function testNullIsNoResourceAndAReferenceIsItself(): void
    {
        $reference = ResourceReference::record('post', '42', new Reference('stub_tenant', '7'));

        self::assertNull(ResourceReferences::of(null));
        self::assertSame($reference, ResourceReferences::of($reference));
    }

    /**
     * A saved model is a record of its morph class and key, with no tenant when
     * the resolver knows none.
     *
     * @return void
     */
    public function testASavedModelIsARecordOfItsMorphClassAndKey(): void
    {
        $model = self::model(42);

        self::assertEquals(ResourceReference::record($model->getMorphClass(), '42'), ResourceReferences::of($model));
        self::assertEquals(ResourceReference::record($model->getMorphClass(), '0'), ResourceReferences::of(self::model(0)));
        self::assertCount(2, $this->resolver->asked);
    }

    /**
     * A saved model's tenant is the one the bound resolver reads for it, and
     * its type the morph class under the application's morph map.
     *
     * @return void
     */
    public function testASavedModelCarriesTheTenantTheResolverReads(): void
    {
        $tenant = new Reference('stub_tenant', '7');
        $model  = self::model('abc');

        $this->bindResolver($tenant);

        Relation::morphMap(['post' => $model::class]);

        $reference = ResourceReferences::of($model);

        self::assertInstanceOf(ResourceReference::class, $reference);
        self::assertSame('post:abc', $reference->identifier);
        self::assertSame('post', $reference->type);
        self::assertSame('abc', $reference->id);
        self::assertSame($tenant, $reference->tenant);
    }

    /**
     * An unsaved model, or one whose key is empty or not a scalar, cannot be
     * identified, and its tenant is never asked for.
     *
     * @return void
     */
    public function testAModelWithoutAKeyCannotBeIdentified(): void
    {
        self::assertFalse(ResourceReferences::of(self::model(null)));
        self::assertFalse(ResourceReferences::of(self::model('')));
        self::assertFalse(ResourceReferences::of(self::model(['a'])));
        self::assertCount(0, $this->resolver->asked);
    }

    /**
     * The resource contract wins over a model's own record and its resolved
     * tenant, saved or not.
     *
     * @return void
     */
    public function testTheResourceContractWinsOverTheModel(): void
    {
        $this->bindResolver(new Reference('stub_tenant', '7'));

        $resource = new class extends Model implements AuthorizableResource {
            /**
             * @return \SineMacula\Laravel\Authorization\Support\ResourceReference
             */
            #[\Override]
            public function toResourceReference(): ResourceReference
            {
                return ResourceReference::record('document', '7');
            }
        };

        self::assertEquals(ResourceReference::record('document', '7'), ResourceReferences::of($resource));

        $resource->setRawAttributes(['id' => 42]);

        self::assertEquals(ResourceReference::record('document', '7'), ResourceReferences::of($resource));
        self::assertCount(0, $this->resolver->asked);
    }

    /**
     * A model class names its type alone, under the application's morph map,
     * with no id or tenant.
     *
     * @return void
     */
    public function testAModelClassNamesItsTypeAlone(): void
    {
        self::assertEquals(ResourceReference::type(StubTenant::class), ResourceReferences::of(StubTenant::class));

        Relation::morphMap(['stub_tenant' => StubTenant::class]);

        $reference = ResourceReferences::of(StubTenant::class);

        self::assertInstanceOf(ResourceReference::class, $reference);
        self::assertSame('stub_tenant:*', $reference->identifier);
        self::assertSame('stub_tenant', $reference->type);
        self::assertNull($reference->id);
        self::assertNull($reference->tenant);
        self::assertCount(0, $this->resolver->asked);
    }

    /**
     * Any other string, a class that is not a model included, is an opaque
     * identifier used as given.
     *
     * @return void
     */
    public function testAnyOtherStringIsAnOpaqueIdentifier(): void
    {
        self::assertEquals(new ResourceReference('post:42'), ResourceReferences::of('post:42'));
        self::assertEquals(new ResourceReference(''), ResourceReferences::of(''));
        self::assertEquals(new ResourceReference(Model::class), ResourceReferences::of(Model::class));
        self::assertEquals(new ResourceReference(\stdClass::class), ResourceReferences::of(\stdClass::class));
        self::assertEquals(new ResourceReference(AuthorizableResource::class), ResourceReferences::of(AuthorizableResource::class));
    }

    /**
     * A `(type, id)` pair names one record of the type, its id a string or a
     * number, with no tenant.
     *
     * @return void
     */
    public function testAPairNamesOneRecord(): void
    {
        self::assertEquals(ResourceReference::record('post', '42'), ResourceReferences::of(['post', '42']));
        self::assertEquals(ResourceReference::record('post', '42'), ResourceReferences::of(['post', 42]));
        self::assertEquals(ResourceReference::record('post', '0'), ResourceReferences::of(['post', 0]));
        self::assertEquals(ResourceReference::record('post', '1.5'), ResourceReferences::of(['post', 1.5]));
        self::assertCount(0, $this->resolver->asked);
    }

    /**
     * A list of any other length, or a keyed array, is not a pair and cannot be
     * identified.
     *
     * @return void
     */
    public function testAnArrayOfAnotherShapeCannotBeIdentified(): void
    {
        self::assertFalse(ResourceReferences::of([]));
        self::assertFalse(ResourceReferences::of(['post:42']));
        self::assertFalse(ResourceReferences::of(['post', '42', 'extra']));
        self::assertFalse(ResourceReferences::of(['type' => 'post', 'id' => '42']));
        self::assertFalse(ResourceReferences::of([1 => 'post', 2 => '42']));
    }

    /**
     * A pair whose type is empty or not a string, or whose id is empty, a
     * boolean or not a scalar, cannot be identified.
     *
     * @return void
     */
    public function testAPairOfTheWrongTypesCannotBeIdentified(): void
    {
        self::assertFalse(ResourceReferences::of(['', '42']));
        self::assertFalse(ResourceReferences::of([7, '42']));
        self::assertFalse(ResourceReferences::of([null, '42']));
        self::assertFalse(ResourceReferences::of(['post', '']));
        self::assertFalse(ResourceReferences::of(['post', true]));
        self::assertFalse(ResourceReferences::of(['post', false]));
        self::assertFalse(ResourceReferences::of(['post', null]));
        self::assertFalse(ResourceReferences::of(['post', ['42']]));
    }

    /**
     * An object that converts to a string is an opaque identifier of that
     * string.
     *
     * @return void
     */
    public function testAStringableObjectIsAnOpaqueIdentifier(): void
    {
        $value = new class {
            /**
             * @return string
             */
            #[\Override]
            public function __toString(): string
            {
                return 'report:9';
            }
        };

        self::assertEquals(new ResourceReference('report:9'), ResourceReferences::of($value));
    }

    /**
     * A number, a boolean or a plain object cannot be identified.
     *
     * @return void
     */
    public function testOtherValuesCannotBeIdentified(): void
    {
        self::assertFalse(ResourceReferences::of(42));
        self::assertFalse(ResourceReferences::of(0));
        self::assertFalse(ResourceReferences::of(1.5));
        self::assertFalse(ResourceReferences::of(true));
        self::assertFalse(ResourceReferences::of(false));
        self::assertFalse(ResourceReferences::of(new \stdClass));
    }

    /**
     * Bind a resource tenant resolver that answers the given tenant for every
     * model.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @return void
     */
    private function bindResolver(?Reference $tenant): void
    {
        $this->resolver = new FixedResourceTenantResolver($tenant);

        Container::getInstance()->instance(ResourceTenantResolver::class, $this->resolver);
    }

    /**
     * Build a model with the given key.
     *
     * @param  mixed  $key
     * @return \Illuminate\Database\Eloquent\Model
     */
    private static function model(mixed $key): Model
    {
        $model = new class extends Model {
            /** @var bool The key is set by hand. */
            public $incrementing = false;
        };

        $model->setRawAttributes(['id' => $key]);

        return $model;
    }
}
