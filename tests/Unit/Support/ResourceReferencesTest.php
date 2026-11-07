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
use Tests\Feature\Stubs\AbstractStubModel;
use Tests\Feature\Stubs\ConstructedStubModel;
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
     * Forget the container, clear the morph map and reset the count of models
     * constructed.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Container::setInstance(null);
        Relation::morphMap([], false);
        ConstructedStubModel::$constructed = 0;

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
     * The identifier of a resolved reference is the one it carries, and there
     * is none for no resource or one that cannot be identified.
     *
     * @return void
     */
    public function testTheIdentifierOfAReferenceIsTheOneItCarries(): void
    {
        self::assertSame('post:42', ResourceReferences::identifierOf(ResourceReference::record('post', '42')));
        self::assertSame('post:*', ResourceReferences::identifierOf(ResourceReference::type('post')));
        self::assertNull(ResourceReferences::identifierOf(null));
        self::assertNull(ResourceReferences::identifierOf(false));
    }

    /**
     * A saved model is a record of its morph class and key, with no tenant when
     * the resolver knows none, and keeps the model itself.
     *
     * @return void
     */
    public function testASavedModelIsARecordOfItsMorphClassAndKey(): void
    {
        $model     = self::model(42);
        $zero      = self::model(0);
        $reference = ResourceReferences::of($model);

        self::assertEquals(ResourceReference::record($model->getMorphClass(), '42', null, $model), $reference);
        self::assertSame($model, $reference instanceof ResourceReference ? $reference->model : null);
        self::assertEquals(ResourceReference::record($zero->getMorphClass(), '0', null, $zero), ResourceReferences::of($zero));
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
     * tenant, saved or not, and the model is handed on with its record.
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

        self::assertEquals(ResourceReference::record('document', '7', null, $resource), ResourceReferences::of($resource));

        $resource->setRawAttributes(['id' => 42]);

        self::assertEquals(ResourceReference::record('document', '7', null, $resource), ResourceReferences::of($resource));
        self::assertCount(0, $this->resolver->asked);
    }

    /**
     * A model implementing the resource contract is handed on with the record
     * its contract names when that reference carries no model, keeping the
     * contract's identifier, type, id and tenant; a model the reference already
     * carries, and a reference that names no one record, are kept as given.
     *
     * @return void
     */
    public function testAModelResourceIsHandedOnWithTheRecordItsContractNames(): void
    {
        $tenant = new Reference('stub_tenant', '3');
        $other  = self::model(9);

        $record = new ResourceReference('docs/7', 'document', '7', $tenant);
        $model  = self::resourceModel($record);

        $reference = ResourceReferences::of($model);

        self::assertInstanceOf(ResourceReference::class, $reference);
        self::assertSame(['docs/7', 'document', '7', $tenant, $model], [$reference->identifier, $reference->type, $reference->id, $reference->tenant, $reference->model]);

        $source = self::resourceModel(new ResourceReference('docs/8'));
        $handed = ResourceReferences::of(self::resourceModel(new ResourceReference('docs/8', 'document', '8', null, null, $source)));

        self::assertSame($source, $handed instanceof ResourceReference ? $handed->source : null);

        $carried = ResourceReference::record('document', '7', null, $other);

        self::assertSame($carried, ResourceReferences::of(self::resourceModel($carried)));

        foreach ([ResourceReference::type('document'), new ResourceReference('document:7')] as $unnamed) {
            self::assertSame($unnamed, ResourceReferences::of(self::resourceModel($unnamed)));
        }
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
     * A pair whose type is a model class names the record by the model's morph
     * class, as the model itself would, under the application's morph map, and
     * the resolver is asked about the record by that type.
     *
     * @return void
     */
    public function testAPairOfAModelClassNamesItsMorphClass(): void
    {
        self::assertEquals(ResourceReference::record(StubTenant::class, 'abc'), ResourceReferences::of([StubTenant::class, 'abc']));

        Relation::morphMap(['stub_tenant' => StubTenant::class]);

        $reference = ResourceReferences::of([StubTenant::class, 'abc']);

        self::assertInstanceOf(ResourceReference::class, $reference);
        self::assertSame('stub_tenant:abc', $reference->identifier);
        self::assertSame('stub_tenant', $reference->type);
        self::assertSame([[StubTenant::class, 'abc'], ['stub_tenant', 'abc']], $this->resolver->askedRecords);
        self::assertCount(0, $this->resolver->asked);
    }

    /**
     * A pair's tenant is the one the bound resolver gives its record, asked
     * once with the pair's type and its id as a string.
     *
     * @return void
     */
    public function testAPairCarriesTheTenantTheResolverGivesItsRecord(): void
    {
        $tenant = new Reference('stub_tenant', '7');

        $this->bindResolver(null, $tenant);

        $reference = ResourceReferences::of(['post', 42]);

        self::assertInstanceOf(ResourceReference::class, $reference);
        self::assertSame('post:42', $reference->identifier);
        self::assertSame($tenant, $reference->tenant);
        self::assertSame([['post', '42']], $this->resolver->askedRecords);
        self::assertCount(0, $this->resolver->asked);
    }

    /**
     * A pair whose record's tenant the resolver cannot tell cannot be
     * identified, rather than being taken as a record of no tenant.
     *
     * @return void
     */
    public function testAPairWhoseTenantCannotBeToldCannotBeIdentified(): void
    {
        $this->bindResolver(null, false);

        self::assertFalse(ResourceReferences::of(['post', '42']));
        self::assertSame([['post', '42']], $this->resolver->askedRecords);
    }

    /**
     * A pair's record is named without a tenant and without asking the
     * resolver, even one that cannot tell its tenant; a pair that names no
     * record is refused the same way as it is with a tenant.
     *
     * @return void
     */
    public function testAPairsRecordIsNamedWithoutAskingTheResolver(): void
    {
        $this->bindResolver(null, false);

        Relation::morphMap(['stub_tenant' => StubTenant::class]);

        self::assertEquals(ResourceReference::record('post', '42'), ResourceReferences::recordOf(['post', 42]));
        self::assertEquals(ResourceReference::record('stub_tenant', 'abc'), ResourceReferences::recordOf([StubTenant::class, 'abc']));

        $unnamed = [['post'], ['post', ''], ['', '1'], ["po\0st", '1'], ['post', "4\0"], [7, '1'], ['post', true]];

        foreach ([...$unnamed, [AbstractStubModel::class, '1'], ['a' => 'post', 'b' => '1']] as $pair) {
            self::assertFalse(ResourceReferences::recordOf($pair));
        }

        self::assertSame([], $this->resolver->askedRecords);
    }

    /**
     * An abstract model class names no type a record can be of, so neither the
     * class nor a pair of it can be identified, and no tenant is asked for.
     *
     * @return void
     */
    public function testAnAbstractModelClassCannotBeIdentified(): void
    {
        self::assertFalse(ResourceReferences::of(AbstractStubModel::class));
        self::assertFalse(ResourceReferences::of([AbstractStubModel::class, '42']));
        self::assertSame([], $this->resolver->askedRecords);
    }

    /**
     * A model class whose constructor needs an argument still names its type,
     * alone or in a pair, under the morph map too, and its constructor never
     * runs.
     *
     * @return void
     */
    public function testAModelClassIsNamedWithoutRunningItsConstructor(): void
    {
        self::assertEquals(ResourceReference::type(ConstructedStubModel::class), ResourceReferences::of(ConstructedStubModel::class));
        self::assertEquals(ResourceReference::record(ConstructedStubModel::class, '42'), ResourceReferences::of([ConstructedStubModel::class, 42]));

        Relation::morphMap(['constructed' => ConstructedStubModel::class]);

        self::assertEquals(ResourceReference::type('constructed'), ResourceReferences::of(ConstructedStubModel::class));
        self::assertEquals(ResourceReference::record('constructed', '42'), ResourceReferences::of([ConstructedStubModel::class, 42]));
        self::assertSame(0, ConstructedStubModel::$constructed);
    }

    /**
     * A pair's id of zero, as a number or a string, is a key; an empty string
     * and a boolean are not, whatever they would be cast to.
     *
     * @return void
     */
    public function testZeroIsAKeyButAnEmptyStringAndABooleanAreNot(): void
    {
        self::assertEquals(ResourceReference::record('post', '0'), ResourceReferences::of(['post', 0]));
        self::assertEquals(ResourceReference::record('post', '0'), ResourceReferences::of(['post', '0']));
        self::assertEquals(ResourceReference::record('post', '0'), ResourceReferences::of(['post', 0.0]));
        self::assertFalse(ResourceReferences::of(['post', '']));
        self::assertFalse(ResourceReferences::of(['post', true]));
        self::assertFalse(ResourceReferences::of(['post', false]));
        self::assertSame([['post', '0'], ['post', '0'], ['post', '0']], $this->resolver->askedRecords);
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
     * An identifier holding a NUL byte names nothing, so it cannot be
     * identified however it is given, and the resolver is never asked about a
     * pair of one.
     *
     * @return void
     */
    public function testAnIdentifierHoldingANulByteCannotBeIdentified(): void
    {
        $this->bindResolver(null, new Reference('stub_tenant', '7'));

        $stringable = new class {
            /**
             * @return string
             */
            #[\Override]
            public function __toString(): string
            {
                return "report:9\0";
            }
        };

        self::assertFalse(ResourceReferences::of("report:9\0"));
        self::assertFalse(ResourceReferences::of(['post', "42\0"]));
        self::assertFalse(ResourceReferences::of(["post\0", '42']));
        self::assertFalse(ResourceReferences::of(new ResourceReference("report\0")));
        self::assertFalse(ResourceReferences::of(ResourceReference::record('post', "4\x002")));
        self::assertFalse(ResourceReferences::of($stringable));
        self::assertFalse(ResourceReferences::of(self::model("4\x002")));
        self::assertSame([], $this->resolver->askedRecords);
    }

    /**
     * An anonymous model class's name, and so its morph class, holds a NUL
     * byte, so its records cannot be identified unless a morph map names them.
     *
     * @return void
     */
    public function testARecordOfAnAnonymousModelClassCannotBeIdentified(): void
    {
        $model = new class extends Model {};

        $model->setRawAttributes(['id' => 42]);

        self::assertFalse(ResourceReferences::of($model));

        Relation::morphMap(['anonymous' => $model::class]);

        self::assertEquals(ResourceReference::record('anonymous', '42', null, $model), ResourceReferences::of($model));
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
     * Tenants given in place of the bound resolver answer a model's and a
     * pair's tenant, the bound resolver asked about neither; a value that needs
     * no tenant never asks them.
     *
     * @return void
     */
    public function testTenantsGivenAnswerInPlaceOfTheBoundResolver(): void
    {
        $tenant  = new Reference('stub_tenant', '7');
        $given   = new FixedResourceTenantResolver($tenant, false);
        $model   = new StubTenant(['id' => '3']);
        $keyless = new StubTenant;

        $reference = ResourceReferences::of($model, $given);

        self::assertInstanceOf(ResourceReference::class, $reference);
        self::assertSame($tenant, $reference->tenant);
        self::assertFalse(ResourceReferences::of(['post', '42'], $given));
        self::assertFalse(ResourceReferences::of($keyless, $given));
        self::assertFalse(ResourceReferences::of(['post', ''], $given));
        self::assertNull(ResourceReferences::of(null, $given));
        self::assertSame([$model], $given->asked);
        self::assertSame([['post', '42']], $given->askedRecords);
        self::assertSame([], $this->resolver->asked);
        self::assertSame([], $this->resolver->askedRecords);
    }

    /**
     * Bind a resource tenant resolver that answers the given tenant for every
     * model, and the given record tenant for every pair.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\Reference|null  $tenant
     * @param  false|\SineMacula\Laravel\Authorization\Support\Reference|null  $recordTenant
     * @return void
     */
    private function bindResolver(?Reference $tenant, false|Reference|null $recordTenant = null): void
    {
        $this->resolver = new FixedResourceTenantResolver($tenant, $recordTenant);

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
        $model = new StubTenant;

        $model->setRawAttributes(['id' => $key]);

        return $model;
    }

    /**
     * Return a saved model whose resource contract names the given reference.
     *
     * @param  \SineMacula\Laravel\Authorization\Support\ResourceReference  $reference
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authorization\Contracts\AuthorizableResource
     */
    private static function resourceModel(ResourceReference $reference): AuthorizableResource&Model
    {
        $model = new class extends Model implements AuthorizableResource {
            /** @var \SineMacula\Laravel\Authorization\Support\ResourceReference|null The reference the contract names. */
            public ?ResourceReference $reference = null;

            /**
             * Return the reference the contract names.
             *
             * @return \SineMacula\Laravel\Authorization\Support\ResourceReference
             *
             * @throws \LogicException
             */
            #[\Override]
            public function toResourceReference(): ResourceReference
            {
                return $this->reference ?? throw new \LogicException('The model names no reference.');
            }
        };

        $model->reference = $reference;

        $model->setRawAttributes(['id' => 42]);

        return $model;
    }
}
