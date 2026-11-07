<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use Illuminate\Database\Eloquent\Model;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authorization\Contracts\AuthorizableResource;
use SineMacula\Laravel\Authorization\Support\Reference;
use SineMacula\Laravel\Authorization\Support\ResourceReference;

/**
 * Unit tests for `ResourceReference`, the resource a check is about: its type,
 * id, tenant and the identifier statements match against.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @SuppressWarnings("php:S1192")
 */
#[CoversClass(ResourceReference::class)]
final class ResourceReferenceTest extends TestCase
{
    /**
     * An identifier given alone is opaque: used as given, with no type, id or
     * tenant.
     *
     * @return void
     */
    public function testAnIdentifierAloneIsOpaque(): void
    {
        $reference = new ResourceReference('report:9');

        self::assertSame('report:9', $reference->identifier);
        self::assertNull($reference->type);
        self::assertNull($reference->id);
        self::assertNull($reference->tenant);
        self::assertNull($reference->model);
    }

    /**
     * Every part of a reference is kept as given to the constructor.
     *
     * @return void
     */
    public function testKeepsEveryPartGiven(): void
    {
        $tenant = new Reference('stub_tenant', '7');
        $model  = new class extends Model {};
        $source = new class implements AuthorizableResource {
            /**
             * Return the reference to the resource.
             *
             * @return \SineMacula\Laravel\Authorization\Support\ResourceReference
             */
            #[\Override]
            public function toResourceReference(): ResourceReference
            {
                return new ResourceReference('custom');
            }
        };
        $reference = new ResourceReference('custom', 'post', '42', $tenant, $model, $source);

        self::assertSame($source, $reference->source);
        self::assertNull((new ResourceReference('custom'))->source);
        self::assertSame('custom', $reference->identifier);
        self::assertSame('post', $reference->type);
        self::assertSame('42', $reference->id);
        self::assertSame($tenant, $reference->tenant);
        self::assertSame($model, $reference->model);
    }

    /**
     * A record is identified as `type:id`, with no tenant or model unless one
     * is given.
     *
     * @return void
     */
    public function testARecordIsIdentifiedByItsTypeAndId(): void
    {
        $tenant = new Reference('stub_tenant', '7');
        $model  = new class extends Model {};
        $record = ResourceReference::record('post', '42');

        self::assertSame('post:42', $record->identifier);
        self::assertSame('post', $record->type);
        self::assertSame('42', $record->id);
        self::assertNull($record->tenant);
        self::assertNull($record->model);
        self::assertSame($tenant, ResourceReference::record('post', '42', $tenant)->tenant);
        self::assertSame($model, ResourceReference::record('post', '42', null, $model)->model);
    }

    /**
     * A type alone is identified as `type:*`, with no id, so a pattern naming
     * the type covers it and one naming a single record does not.
     *
     * @return void
     */
    public function testATypeAloneIsIdentifiedByItsTypeAndAWildcard(): void
    {
        $tenant = new Reference('stub_tenant', '7');
        $type   = ResourceReference::type('post');

        self::assertSame('post:*', $type->identifier);
        self::assertSame('post', $type->type);
        self::assertNull($type->id);
        self::assertNull($type->tenant);
        self::assertNull($type->model);
        self::assertSame($tenant, ResourceReference::type('post', $tenant)->tenant);
    }

    /**
     * A reference cannot be changed once made.
     *
     * @return void
     */
    public function testIsReadOnly(): void
    {
        self::assertTrue((new \ReflectionClass(ResourceReference::class))->isReadOnly());
    }
}
